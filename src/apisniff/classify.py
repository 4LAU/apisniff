from __future__ import annotations

import functools
import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlparse

import tldextract
import yaml

from apisniff.models import CapturedFlow, ClassifyResult, get_header
from apisniff.surface import (
    CaptureClassificationContext,
    HostRole,
    SurfaceClassification,
)

_SIGNATURES_DIR = Path(__file__).parent / "signatures"

# Offline-only (suffix_list_urls=() disables HTTP fetch per docs). cache_dir=None
# avoids writing tldextract lock files in restricted runtime environments.
# include_psl_private_domains=True so herokuapp.com, github.io, etc.
# are treated as public suffixes — each app is a distinct registrable domain.
_tld_extract = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=True,
)

_JS_CONTENT_TYPES = ("application/javascript", "text/javascript", "application/x-javascript")

_DROPPABLE_CONTENT_TYPES = _JS_CONTENT_TYPES + (
    "text/css", "image/", "video/", "audio/", "font/",
    "application/font", "application/pdf", "application/wasm",
)
_STATIC_CONTENT_TYPE_PREFIXES = _DROPPABLE_CONTENT_TYPES
_API_CONTENT_TYPES = (
    "application/json",
    "application/problem+json",
    "application/hal+json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
)
_API_PATH_FRAGMENTS = ("/api/", "/v1/", "/v2/", "/rest/", "/rpc/", "/graphql")
_AUTH_PATH_FRAGMENTS = (
    "/auth",
    "/login",
    "/logout",
    "/oauth",
    "/sso",
    "/session",
    "/token",
)
_TELEMETRY_PATH_FRAGMENTS = (
    "/analytics",
    "/beacon",
    "/collect",
    "/event",
    "/logging",
    "/metrics",
    "/pageview",
    "/pixel",
    "/rum",
    "/telemetry",
    "/track",
)
_CAPTCHA_HOST_FRAGMENTS = (
    "recaptcha.net",
    "hcaptcha.com",
    "arkoselabs.com",
    "funcaptcha.com",
    "challenges.cloudflare.com",
)
_CAPTCHA_PATH_FRAGMENTS = (
    "/recaptcha/",
    "/captcha/",
    "/hcaptcha/",
    "/cdn-cgi/challenge-platform/",
    "/cdn-cgi/turnstile/",
)
_ANTIBOT_HOST_FRAGMENTS = (
    "datadome.co",
    "datado.me",
    "perimeterx.net",
    "px-cloud.net",
    "px-cdn.net",
    "kasada.io",
    "kpsdk.io",
    "kpsdk.com",
    "online-metrix.net",
    "shapesecurity.com",
    "incapsula.com",
    "impervadns.net",
    "awswaf.com",
)


@functools.lru_cache(maxsize=4)
def _load_yaml(name: str) -> dict | list:
    with open(_SIGNATURES_DIR / name) as f:
        return yaml.safe_load(f)


def extract_registered_domain(hostname: str) -> str:
    h = hostname.lower().rstrip(".")
    if not h:
        return h
    if ":" in h or h.replace(".", "").isdigit():
        return h
    return _tld_extract(h).top_domain_under_public_suffix or h


def _host_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def target_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname or value.split("/", 1)[0]
    return host.lower().rstrip(".")


def _matches_domain_list(domain: str, domain_list: list[str] | tuple[str, ...]) -> bool:
    d = domain.lower()
    return any(d == entry or d.endswith("." + entry) for entry in domain_list)


_SENSOR_DATA_PREFIX = b'{"sensor_data":'

_TELEMETRY_SUBDOMAIN_INDICATORS = ("analytics.", "smetrics.", "telemetry.", "metrics.")


def _contains_any(value: str, fragments: tuple[str, ...] | list[str]) -> bool:
    value = value.lower()
    return any(fragment.lower() in value for fragment in fragments)


def _path_contains_any(path: str, fragments: tuple[str, ...]) -> bool:
    """Match fragments at path-segment boundaries, not as arbitrary substrings."""
    path = path.lower()
    for fragment in fragments:
        frag = fragment.lower()
        idx = 0
        while True:
            idx = path.find(frag, idx)
            if idx < 0:
                break
            end = idx + len(frag)
            if end == len(path) or path[end] == "/":
                return True
            idx += 1
    return False


def _request_content_type(flow: CapturedFlow) -> str:
    return get_header(flow.request_headers, "content-type").split(";")[0].strip().lower()


def _is_jsonish_content_type(content_type: str) -> bool:
    return (
        content_type == "application/json"
        or content_type.endswith("+json")
        or "json" in content_type
    )


def is_api_like(flow: CapturedFlow) -> tuple[bool, str, tuple[str, ...]]:
    path_only = flow.path.split("?", 1)[0].lower()
    response_ct = flow.content_type
    request_ct = _request_content_type(flow)

    if _is_jsonish_content_type(response_ct):
        return True, "response content type is JSON", (f"response_ct:{response_ct}",)
    if request_ct in _API_CONTENT_TYPES or request_ct.endswith("+json"):
        return True, "request content type is API-shaped", (f"request_ct:{request_ct}",)
    if _contains_any(path_only, _API_PATH_FRAGMENTS):
        return True, "path contains API marker", ("path_api_marker",)
    if flow.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        return True, "non-GET method suggests API traffic", ("method_api_signal",)
    body = flow.response_body.lstrip()[:1]
    if body in {b"{", b"["}:
        return True, "response body starts with JSON structure", ("json_body_shape",)
    return False, "not API-shaped traffic", ()


def _looks_like_antibot_payload(flow: CapturedFlow) -> bool:
    if flow.method.upper() != "POST" or not flow.request_body:
        return False
    if flow.request_body.startswith(_SENSOR_DATA_PREFIX):
        return True
    try:
        parsed = json.loads(flow.request_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(parsed, dict):
        return False
    if set(parsed) != {"body"} or not isinstance(parsed["body"], str):
        return False

    body = parsed["body"]
    path_segments = [segment for segment in flow.path.split("?", 1)[0].split("/") if segment]
    if len(body) < 100 or len(path_segments) < 5:
        return False
    punctuation = sum(1 for char in body if not char.isalnum() and not char.isspace())
    return punctuation >= 20


def _host_role(host: str, target_domain: str, context: CaptureClassificationContext) -> HostRole:
    rd = extract_registered_domain(host)
    target_rd = extract_registered_domain(target_domain)
    if host.lower().rstrip(".") == target_domain.lower().rstrip("."):
        return "target"
    if rd == target_rd or rd in context.known_related_domains:
        return "same_site"
    return "third_party"


def classify_flow(
    flow: CapturedFlow,
    target_domain: str,
    context: CaptureClassificationContext | None = None,
) -> SurfaceClassification:
    context = context or CaptureClassificationContext()
    target = target_host(target_domain)
    host = flow.host.lower().rstrip(".")
    path_only = flow.path.split("?", 1)[0].lower()
    role = _host_role(host, target, context)

    if flow.method.upper() == "OPTIONS":
        return SurfaceClassification(
            category="options",
            reason="CORS preflight OPTIONS request",
            api_like=False,
            host_role=role,
            signals=("method:OPTIONS",),
        )

    api_like, api_reason, api_signals = is_api_like(flow)

    if _matches_domain_list(host, _CAPTCHA_HOST_FRAGMENTS) or _contains_any(
        path_only, _CAPTCHA_PATH_FRAGMENTS
    ):
        return SurfaceClassification(
            category="captcha",
            reason="captcha or browser challenge traffic",
            api_like=api_like,
            host_role=role,
            signals=api_signals + ("captcha_signature",),
        )

    indicators = _load_yaml("challenge_indicators.yaml")
    if (
        _looks_like_antibot_payload(flow)
        or _matches_domain_list(host, _ANTIBOT_HOST_FRAGMENTS)
        or _matches_domain_list(host, tuple(indicators.get("allowlist_domains", [])))
        or _contains_any(path_only, indicators.get("allowlist_paths", []))
    ):
        return SurfaceClassification(
            category="antibot",
            reason="bot-defense sensor or challenge traffic",
            api_like=api_like,
            host_role=role,
            signals=api_signals + ("antibot_signature",),
        )

    telemetry_substrings = (
        tuple(indicators.get("drop_path_substrings", []))
        + tuple(indicators.get("same_site_drop_paths", []))
    )
    noise_domains = _load_yaml("noise_domains.yaml")
    if (
        _contains_any(path_only, telemetry_substrings)
        or _path_contains_any(path_only, _TELEMETRY_PATH_FRAGMENTS)
    ):
        return SurfaceClassification(
            category="telemetry",
            reason="telemetry, logging, analytics, or beacon path",
            api_like=api_like,
            host_role=role,
            signals=api_signals + ("telemetry_path",),
        )
    host_lower = host.lower()
    if role != "third_party" and any(
        host_lower.startswith(ind) or f".{ind}" in host_lower
        for ind in _TELEMETRY_SUBDOMAIN_INDICATORS
    ):
        return SurfaceClassification(
            category="telemetry",
            reason="same-site telemetry subdomain",
            api_like=api_like,
            host_role=role,
            signals=api_signals + ("telemetry_subdomain",),
        )
    if _matches_domain_list(host, noise_domains):
        category = (
            "telemetry"
            if api_like or _contains_any(path_only, _TELEMETRY_PATH_FRAGMENTS)
            else "non_api"
        )
        return SurfaceClassification(
            category=category,
            reason="known telemetry, analytics, ad, or noise domain",
            api_like=api_like,
            host_role=role,
            signals=api_signals + ("noise_domain",),
        )

    if flow.content_type.startswith(_STATIC_CONTENT_TYPE_PREFIXES):
        if (
            flow.content_type in _JS_CONTENT_TYPES
            and len(_scan_antibot_markers(flow.response_body)) >= 2
        ):
            return SurfaceClassification(
                category="antibot",
                reason="JavaScript contains bot-defense markers",
                api_like=False,
                host_role=role,
                signals=("antibot_js",),
            )
        return SurfaceClassification(
            category="static",
            reason="static asset",
            api_like=False,
            host_role=role,
            signals=(f"response_ct:{flow.content_type}",),
        )

    if not api_like:
        return SurfaceClassification(
            category="non_api",
            reason=api_reason,
            api_like=False,
            host_role=role,
            signals=api_signals,
        )

    if _path_contains_any(path_only, _AUTH_PATH_FRAGMENTS):
        return SurfaceClassification(
            category="auth",
            reason="auth API",
            api_like=True,
            host_role=role,
            signals=api_signals + ("auth_path",),
        )

    if role == "third_party":
        return SurfaceClassification(
            category="third_party_api",
            reason="API-shaped traffic on another host",
            api_like=True,
            host_role=role,
            signals=api_signals,
        )

    if role == "same_site" and host != target:
        return SurfaceClassification(
            category="unknown_api_like",
            reason="same-site API-shaped traffic outside requested host",
            api_like=True,
            host_role=role,
            signals=api_signals,
        )

    return SurfaceClassification(
        category="business_api",
        reason=api_reason if api_reason != "not API-shaped traffic" else "target API traffic",
        api_like=True,
        host_role=role,
        signals=api_signals,
    )


class Classifier:
    def __init__(self, target_domain: str) -> None:
        self._target_host = target_host(target_domain)
        self._target_rd = extract_registered_domain(self._target_host)
        self._related_domains: set[str] = set()
        self._noise_domains: list[str] = _load_yaml("noise_domains.yaml")

    def classify(self, flow: CapturedFlow) -> ClassifyResult:
        if flow.method.upper() != "OPTIONS":
            self._learn_csp(flow)
            self._learn_request_relationship(flow)

        surface = classify_flow(flow, self._target_host, self.context())
        if surface.category == "options":
            return ClassifyResult(action="drop", category="options", flow=None)

        tags = [tag for tag in flow.tags if not tag.startswith("surface:")]
        tags.append(f"surface:{surface.category}")
        if surface.category in {"antibot", "captcha"}:
            tags.append("allowlisted")
        if "antibot_js" in surface.signals:
            tags.append("antibot_js")
        return ClassifyResult(
            action="keep",
            category=surface.category,
            flow=replace(flow, tags=tags),
        )

    def classify_surface(self, flow: CapturedFlow) -> SurfaceClassification:
        if flow.method.upper() != "OPTIONS":
            self._learn_csp(flow)
            self._learn_request_relationship(flow)
        return classify_flow(flow, self._target_host, self.context())

    def context(self) -> CaptureClassificationContext:
        return CaptureClassificationContext(
            known_related_domains=tuple(sorted(self._related_domains))
        )

    def _learn_request_relationship(self, flow: CapturedFlow) -> None:
        rd = extract_registered_domain(flow.host)
        if rd == self._target_rd:
            return
        referer = flow.request_headers.get("referer", "")
        origin = flow.request_headers.get("origin", "")
        for val in (referer, origin):
            if val:
                h = _host_from_url(val)
                if h and extract_registered_domain(h) == self._target_rd:
                    self._related_domains.add(rd)
                    return

    def _learn_csp(self, flow: CapturedFlow) -> None:
        csp = flow.response_headers.get("content-security-policy", "")
        if not csp:
            return
        for directive in csp.split(";"):
            parts = directive.strip().split()
            for token in parts[1:]:
                token = token.strip("'\"")
                if not token or "." not in token:
                    continue
                host = token.lstrip("*.")
                if "//" in host:
                    host = host.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
                if not host or "." not in host:
                    continue
                rd = extract_registered_domain(host)
                if (
                    rd
                    and rd != self._target_rd
                    and not _matches_domain_list(host, self._noise_domains)
                ):
                    self._related_domains.add(rd)


def _scan_antibot_markers(body: bytes) -> list[str]:
    if not body:
        return []
    indicators = _load_yaml("challenge_indicators.yaml")
    text = body[:500_000].decode("utf-8", errors="replace")
    return [m for m in indicators.get("markers", []) if m in text]

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from urllib.parse import urlparse

import tldextract
import yaml

from apisniff.models import CapturedFlow, ClassifyResult

_SIGNATURES_DIR = Path(__file__).parent / "signatures"

# Offline-only (suffix_list_urls=() disables HTTP fetch per docs).
# include_psl_private_domains=True so herokuapp.com, github.io, etc.
# are treated as public suffixes — each app is a distinct registrable domain.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

_JS_CONTENT_TYPES = ("application/javascript", "text/javascript", "application/x-javascript")

_DROPPABLE_CONTENT_TYPES = _JS_CONTENT_TYPES + (
    "text/css", "image/", "video/", "audio/", "font/",
    "application/font", "application/pdf", "application/wasm",
)


def _load_yaml(name: str) -> dict | list:
    with open(_SIGNATURES_DIR / name) as f:
        return yaml.safe_load(f)


def _extract_registered_domain(hostname: str) -> str:
    h = hostname.lower().rstrip(".")
    if not h:
        return h
    if ":" in h or h.replace(".", "").isdigit():
        return h
    return _tld_extract(h).top_domain_under_public_suffix or h


def _host_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _matches_domain_list(domain: str, domain_list: list[str]) -> bool:
    d = domain.lower()
    for entry in domain_list:
        if d == entry or d.endswith("." + entry):
            return True
    return False


class Classifier:
    def __init__(self, target_domain: str) -> None:
        self._target_rd = _extract_registered_domain(target_domain)
        self._related_domains: set[str] = set()

        indicators = _load_yaml("challenge_indicators.yaml")
        self._allowlist_domains: list[str] = indicators.get("allowlist_domains", [])
        self._allowlist_paths: list[str] = indicators.get("allowlist_paths", [])
        self._antibot_markers: list[str] = indicators.get("markers", [])
        self._drop_path_substrings: list[str] = indicators.get("drop_path_substrings", [])
        self._same_site_drop_paths: list[str] = indicators.get("same_site_drop_paths", [])

        self._noise_domains: list[str] = _load_yaml("noise_domains.yaml")

    def classify(self, flow: CapturedFlow) -> ClassifyResult:
        if flow.method == "OPTIONS":
            return ClassifyResult(action="drop", category="options", flow=None)

        tags: list[str] = []
        host = flow.host
        path = flow.path

        # 1. Allowlist
        allowlist_type = self._check_allowlist(flow)
        if allowlist_type:
            tags.append("allowlisted")

        # 2. Noise domains
        if not allowlist_type and _matches_domain_list(host, self._noise_domains):
            return ClassifyResult(action="drop", category="noise_domain", flow=None)

        # Learn from CSP
        self._learn_csp(flow)

        # 3. Path telemetry
        if allowlist_type not in ("domain", "path"):
            if any(s in path for s in self._drop_path_substrings):
                return ClassifyResult(action="drop", category="path_telemetry", flow=None)

        # 4. Third-party
        if not allowlist_type:
            if self._is_third_party(flow):
                return ClassifyResult(action="drop", category="third_party", flow=None)

        # 5. Static assets
        if allowlist_type not in ("domain", "path"):
            ct = flow.content_type
            if any(ct.startswith(t) for t in _DROPPABLE_CONTENT_TYPES):
                if ct in _JS_CONTENT_TYPES:
                    markers = self._scan_antibot_markers(flow.response_body)
                    if len(markers) >= 2:
                        tags.append("antibot_js")
                    else:
                        return ClassifyResult(action="drop", category="static_asset", flow=None)
                else:
                    return ClassifyResult(action="drop", category="static_asset", flow=None)

        # 6. Same-site noise
        if allowlist_type not in ("domain", "path"):
            if any(p in path for p in self._same_site_drop_paths):
                return ClassifyResult(action="drop", category="same_site_noise", flow=None)

        kept = replace(flow, tags=tags)
        return ClassifyResult(action="keep", category="", flow=kept)

    def _check_allowlist(self, flow: CapturedFlow) -> str:
        if _matches_domain_list(flow.host, self._allowlist_domains):
            return "domain"
        if any(frag in flow.path for frag in self._allowlist_paths):
            return "path"
        return ""

    def _is_third_party(self, flow: CapturedFlow) -> bool:
        rd = _extract_registered_domain(flow.host)
        if rd == self._target_rd:
            return False
        if rd in self._related_domains:
            return False
        referer = flow.request_headers.get("referer", "")
        origin = flow.request_headers.get("origin", "")
        for val in (referer, origin):
            if val:
                h = _host_from_url(val)
                if h and _extract_registered_domain(h) == self._target_rd:
                    self._related_domains.add(rd)
                    return False
        return True

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
                rd = _extract_registered_domain(host)
                if rd and rd != self._target_rd:
                    if not _matches_domain_list(host, self._noise_domains):
                        self._related_domains.add(rd)

    def _scan_antibot_markers(self, body: bytes) -> list[str]:
        if not body:
            return []
        text = body[:500_000].decode("utf-8", errors="replace")
        return [m for m in self._antibot_markers if m in text]

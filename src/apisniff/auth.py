from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from apisniff.models import CapturedFlow

_SESSION_COOKIE_NAMES = frozenset({
    "session", "sessionid", "sid", "jsessionid", "phpsessid",
    "connect.sid", "_session_id", "laravel_session",
})

_API_KEY_HEADERS = frozenset({"x-api-key", "api-key", "apikey"})
_API_KEY_QUERY_PARAMS = frozenset({"api_key", "apikey", "key"})
_TOKEN_PATHS = frozenset({"/oauth/token", "/auth/token", "/token"})


@dataclass(frozen=True)
class AuthPattern:
    auth_type: str
    detail: str
    flow_count: int


def detect_auth(flows: list[CapturedFlow]) -> list[AuthPattern]:
    counts: Counter[tuple[str, str]] = Counter()

    for flow in flows:
        headers = flow.request_headers
        path = flow.path.split("?")[0].rstrip("/")

        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            counts[("bearer", "authorization: bearer")] += 1
        elif auth_header.lower().startswith("basic "):
            counts[("basic", "authorization: basic")] += 1

        for hdr in _API_KEY_HEADERS:
            if hdr in headers:
                counts[("api_key_header", hdr)] += 1

        parsed = urlparse(flow.url)
        qs = parse_qs(parsed.query)
        for param in _API_KEY_QUERY_PARAMS:
            if param in qs:
                counts[("api_key_query", param)] += 1

        cookie_val = headers.get("cookie", "")
        if cookie_val:
            for part in cookie_val.split(";"):
                name = part.strip().split("=", 1)[0].strip().lower()
                if name in _SESSION_COOKIE_NAMES:
                    counts[("session_cookie", name)] += 1

        if path.lower() in _TOKEN_PATHS:
            counts[("token_endpoint", path)] += 1

    return sorted(
        [AuthPattern(auth_type=k[0], detail=k[1], flow_count=v) for k, v in counts.items()],
        key=lambda p: p.flow_count,
        reverse=True,
    )


@dataclass(frozen=True)
class ExtractedCookie:
    name: str
    value: str
    domain: str
    host_only: bool
    path: str
    secure: bool
    source: str


def _parse_set_cookie(raw: str, host: str) -> ExtractedCookie | None:
    parts = raw.split(";")
    nv = parts[0].strip()
    if "=" not in nv:
        return None
    name, value = nv.split("=", 1)
    name = name.strip()
    if not name:
        return None

    domain = host
    path = "/"
    secure = False
    host_only = True

    for attr in parts[1:]:
        attr = attr.strip()
        if "=" in attr:
            akey, aval = attr.split("=", 1)
        else:
            akey, aval = attr, ""
        akey = akey.strip().lower()
        aval = aval.strip()
        if akey == "domain":
            domain = aval.lstrip(".")
            host_only = False
        elif akey == "path":
            path = aval or "/"
        elif akey == "secure":
            secure = True

    return ExtractedCookie(
        name=name, value=value, domain=domain, host_only=host_only,
        path=path, secure=secure, source="response",
    )


def extract_cookies(flows: list[CapturedFlow]) -> list[ExtractedCookie]:
    seen: dict[tuple[str, str, str], tuple[float, ExtractedCookie]] = {}

    for flow in sorted(flows, key=lambda f: f.timestamp):
        host = flow.host

        cookie_val = flow.request_headers.get("cookie", "")
        if cookie_val:
            for part in cookie_val.split(";"):
                part = part.strip()
                if "=" not in part:
                    continue
                name, value = part.split("=", 1)
                name = name.strip()
                if not name:
                    continue
                c = ExtractedCookie(
                    name=name, value=value.strip(), domain=host,
                    host_only=True, path="/", secure=False, source="request",
                )
                key = (c.name, c.domain, c.path)
                seen[key] = (flow.timestamp, c)

        sc_val = flow.response_headers.get("set-cookie", "")
        if sc_val:
            for line in sc_val.split("\n"):
                line = line.strip()
                if not line:
                    continue
                c = _parse_set_cookie(line, host)
                if c:
                    key = (c.name, c.domain, c.path)
                    seen[key] = (flow.timestamp, c)

    return [cookie for _, cookie in sorted(seen.values(), key=lambda x: x[0])]


def cookies_to_cookiejar(cookies: list[ExtractedCookie]) -> str:
    lines: list[str] = []
    for c in cookies:
        if c.source != "response":
            continue
        domain = f".{c.domain}" if not c.host_only else c.domain
        flag = "FALSE" if c.host_only else "TRUE"
        secure = "TRUE" if c.secure else "FALSE"
        lines.append(f"{domain}\t{flag}\t{c.path}\t{secure}\t0\t{c.name}\t{c.value}")
    return "\n".join(lines) + "\n" if lines else ""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

_CHALLENGE_MARKERS = (
    "challenges.cloudflare.com",
    "challenge-platform",
    "managed_challenge",
    "jschl_vc",
    "_cf_chl_opt",
    "cf-please-wait",
)

_BLOCK_STATUSES = frozenset({403, 429, 503, 999})


class ProbeVerdict(enum.Enum):
    NO_PROTECTION = "no_protection"
    CLIENT_DEPENDENT = "client_dependent"
    JS_CHALLENGE = "js_challenge"
    FULL_BLOCK = "full_block"


@dataclass(frozen=True, slots=True)
class CapturedFlow:
    method: str
    host: str
    path: str
    url: str
    request_headers: dict[str, str]
    request_body: bytes
    response_status: int
    response_headers: dict[str, str]
    response_body: bytes
    tags: list[str] = field(default_factory=list)
    timestamp: float = 0.0

    @property
    def content_type(self) -> str:
        ct = ""
        for k, v in self.response_headers.items():
            if k.lower() == "content-type":
                ct = v
                break
        return ct.split(";")[0].strip().lower()


@dataclass(frozen=True, slots=True)
class ProbeResult:
    label: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    error: str | None

    @property
    def is_blocked(self) -> bool:
        if self.error:
            return True
        if self.status is None:
            return True
        if self.status in _BLOCK_STATUSES:
            return True
        return self.is_challenge

    @property
    def is_challenge(self) -> bool:
        if self.error or not self.body:
            return False
        text = self.body[:50_000].decode("utf-8", errors="replace").lower()
        return any(marker in text for marker in _CHALLENGE_MARKERS)


@dataclass(frozen=True, slots=True)
class VendorMatch:
    vendor: str
    confidence: str  # "high", "medium", "low"
    signals: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ProbeAssessment:
    url: str
    verdict: ProbeVerdict
    recommendation: str
    results: dict[str, ProbeResult]  # label → result
    vendors: list[VendorMatch] = field(default_factory=list)
    graphql_endpoints: list[str] = field(default_factory=list)
    graphql_introspection: bool = False

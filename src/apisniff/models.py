from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Literal

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

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body.decode("utf-8", errors="replace"),
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body.decode("utf-8", errors="replace"),
            "tags": self.tags,
            "timestamp": self.timestamp,
        }

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> CapturedFlow:
        return cls(
            method=d["method"],
            host=d["host"],
            path=d["path"],
            url=d["url"],
            request_headers=d.get("request_headers", {}),
            request_body=d.get("request_body", "").encode("utf-8"),
            response_status=d.get("response_status", 0),
            response_headers=d.get("response_headers", {}),
            response_body=d.get("response_body", "").encode("utf-8"),
            tags=d.get("tags", []),
            timestamp=d.get("timestamp", 0.0),
        )

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
    graphql_schema_path: str | None = None


_DropCategory = Literal[
    "options", "noise_domain", "path_telemetry",
    "third_party", "static_asset", "same_site_noise",
]


@dataclass(frozen=True, slots=True)
class ClassifyResult:
    action: Literal["keep", "drop"]
    category: _DropCategory | str
    flow: CapturedFlow | None


@dataclass(frozen=True, slots=True)
class SessionStats:
    domain: str
    started_at: str
    duration_seconds: float
    total_flows: int
    kept_flows: int
    dropped: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "started_at": self.started_at,
            "duration_seconds": self.duration_seconds,
            "total_flows": self.total_flows,
            "kept_flows": self.kept_flows,
            "dropped": dict(self.dropped),
        }

    @classmethod
    def from_dict(cls, d: dict) -> SessionStats:
        return cls(
            domain=d["domain"],
            started_at=d["started_at"],
            duration_seconds=d["duration_seconds"],
            total_flows=d["total_flows"],
            kept_flows=d["kept_flows"],
            dropped=d.get("dropped", {}),
        )

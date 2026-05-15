from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from apisniff.models import CapturedFlow

SurfaceCategory = Literal[
    "business_api",
    "auth",
    "antibot",
    "captcha",
    "telemetry",
    "third_party_api",
    "static",
    "non_api",
    "unknown_api_like",
    "options",
]

HostRole = Literal["target", "same_site", "third_party"]

CLASSIFIER_VERSION = "surface-v1"
CAPTURE_CONTEXT_VERSION = "capture-context-v1"

IMPORTANT_SURFACE_CATEGORIES = frozenset({
    "business_api",
    "auth",
    "antibot",
    "captcha",
    "telemetry",
    "third_party_api",
    "unknown_api_like",
})


@dataclass(frozen=True, slots=True)
class CaptureClassificationContext:
    known_related_domains: tuple[str, ...] = ()
    context_version: str = CAPTURE_CONTEXT_VERSION

    def to_dict(self) -> dict:
        return {
            "context_version": self.context_version,
            "known_related_domains": list(self.known_related_domains),
        }

    @classmethod
    def from_dict(cls, value: dict) -> CaptureClassificationContext:
        domains = value.get("known_related_domains", ())
        if not isinstance(domains, list | tuple):
            domains = ()
        return cls(
            known_related_domains=tuple(sorted(str(d).lower() for d in domains if d)),
            context_version=str(value.get("context_version") or CAPTURE_CONTEXT_VERSION),
        )


@dataclass(frozen=True, slots=True)
class SurfaceClassification:
    category: SurfaceCategory
    reason: str
    api_like: bool
    host_role: HostRole
    classifier_version: str = CLASSIFIER_VERSION
    signals: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "classifier_version": self.classifier_version,
            "category": self.category,
            "reason": self.reason,
            "api_like": self.api_like,
            "host_role": self.host_role,
            "signals": list(self.signals),
        }

    @classmethod
    def from_dict(cls, value: dict) -> SurfaceClassification:
        category = value.get("category")
        host_role = value.get("host_role")
        if category not in SurfaceCategory.__args__:
            raise ValueError(f"unknown surface category: {category!r}")
        if host_role not in HostRole.__args__:
            raise ValueError(f"unknown host role: {host_role!r}")
        signals = value.get("signals", ())
        if not isinstance(signals, list | tuple):
            signals = ()
        return cls(
            category=category,
            reason=str(value.get("reason") or ""),
            api_like=bool(value.get("api_like")),
            host_role=host_role,
            classifier_version=str(value.get("classifier_version") or ""),
            signals=tuple(str(signal) for signal in signals),
        )


def write_capture_context(bundle_dir: Path, context: CaptureClassificationContext) -> None:
    (bundle_dir / "surface-context.json").write_text(json.dumps(context.to_dict(), indent=2))


def read_capture_context(bundle_dir: Path) -> CaptureClassificationContext | None:
    path = bundle_dir / "surface-context.json"
    if not path.exists():
        return None
    try:
        return CaptureClassificationContext.from_dict(json.loads(path.read_text()))
    except (json.JSONDecodeError, OSError, ValueError, TypeError):
        return None


def write_surface_metadata(bundle_dir: Path, records: list[dict]) -> None:
    path = bundle_dir / "surface.jsonl"
    with path.open("w") as f:
        for record in records:
            f.write(json.dumps(record, sort_keys=True) + "\n")


def read_surface_metadata(
    bundle_dir: Path,
    expected_context: CaptureClassificationContext,
    expected_flows: list[CapturedFlow],
) -> dict[int, SurfaceClassification]:
    path = bundle_dir / "surface.jsonl"
    if not path.exists():
        return {}

    records: dict[int, SurfaceClassification] = {}
    expected_context_dict = expected_context.to_dict()
    try:
        with path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                raw = json.loads(line)
                if raw.get("capture_context") != expected_context_dict:
                    return {}
                index = int(raw["flow_index"])
                if index < 0 or index >= len(expected_flows):
                    return {}
                expected_flow = expected_flows[index]
                if (
                    raw.get("method") != expected_flow.method.upper()
                    or raw.get("host") != expected_flow.host.lower().rstrip(".")
                    or raw.get("path") != expected_flow.path
                ):
                    return {}
                classification = SurfaceClassification.from_dict(raw["classification"])
                if classification.classifier_version != CLASSIFIER_VERSION:
                    return {}
                records[index] = classification
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return {}
    if len(records) != len(expected_flows):
        return {}
    return records

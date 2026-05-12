from __future__ import annotations

import json
from pathlib import Path
from typing import IO

from apisniff.models import CapturedFlow

CAPTURES_DIR = Path.home() / "apisniff-captures"


def safe_bundle_name(domain: str) -> str:
    return domain.replace(".", "-").replace("/", "-")


def find_latest_bundle(domain: str) -> Path | None:
    safe = safe_bundle_name(domain)
    candidates = sorted(
        (p for p in CAPTURES_DIR.glob(f"{safe}_*") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


def write_flow_jsonl(f: IO, flow: CapturedFlow) -> None:
    f.write(flow.to_jsonl() + "\n")
    f.flush()


def read_capture_jsonl(path: str) -> list[CapturedFlow]:
    flows: list[CapturedFlow] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                flows.append(CapturedFlow.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
    return flows


def detect_input_format(head: str) -> str:
    stripped = head.strip()
    if stripped.startswith('{"log"'):
        return "har"
    if stripped.startswith("{") and '"method"' in stripped:
        return "jsonl"
    if "<?xml" in stripped and "<items" in stripped:
        return "burp"
    return "unknown"


def load_flows(path: str) -> tuple[list[CapturedFlow], str]:
    """Load flows from HAR, Burp XML, or JSONL file. Returns (flows, format)."""
    p = Path(path)
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            head = f.read(1024)
    except OSError:
        return [], "unknown"
    fmt = detect_input_format(head)
    if fmt == "har":
        from apisniff.adapters.har import har_to_flows
        flows = har_to_flows(p.read_text())
    elif fmt == "burp":
        from apisniff.adapters.burp import burp_to_flows
        flows = burp_to_flows(p.read_text())
    elif fmt == "jsonl":
        flows = read_capture_jsonl(path)
    else:
        flows = []
    return flows, fmt

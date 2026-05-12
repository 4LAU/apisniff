from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

import yaml

from apisniff.auth import detect_auth, extract_cookies
from apisniff.bundle import read_capture_jsonl
from apisniff.models import CapturedFlow, normalize_path
from apisniff.report import generate_report
from apisniff.spec import _is_api_flow, generate_openapi


def generate_inventory(flows: list[CapturedFlow]) -> list[dict]:
    groups: dict[tuple[str, str], list[CapturedFlow]] = defaultdict(list)
    for flow in flows:
        key = (flow.method.upper(), normalize_path(flow.path))
        groups[key].append(flow)

    inventory: list[dict] = []
    for (method, path), group in sorted(groups.items()):
        status_codes = sorted({f.response_status for f in group})
        content_types = sorted({f.content_type for f in group if f.content_type})
        inventory.append({
            "method": method,
            "path": path,
            "count": len(group),
            "status_codes": status_codes,
            "content_types": content_types,
        })
    return inventory


def _load_session_stats(src_path: Path):
    from apisniff.models import SessionStats
    session_path = src_path / "session.json"
    if not session_path.exists():
        return None
    try:
        return SessionStats.from_dict(json.loads(session_path.read_text()))
    except (json.JSONDecodeError, KeyError):
        return None


def share_bundle(src: str, dst: str, domain: str) -> dict:
    src_path = Path(src)
    dst_path = Path(dst)
    dst_path.mkdir(parents=True, exist_ok=True)

    flows = read_capture_jsonl(str(src_path / "flows.jsonl"))

    api_flows = [f for f in flows if _is_api_flow(f)]
    auth_patterns = detect_auth(flows)
    cookies = extract_cookies(flows)

    spec = generate_openapi(api_flows, domain, auth_patterns=auth_patterns)
    spec_yaml = yaml.dump(spec, sort_keys=False, default_flow_style=False)
    (dst_path / "spec.yaml").write_text(spec_yaml)

    inventory = generate_inventory(flows)
    (dst_path / "inventory.json").write_text(
        json.dumps(inventory, indent=2)
    )

    session_stats = _load_session_stats(src_path)

    from apisniff.models import ProbeResult
    from apisniff.vendors import load_signatures, match_vendors
    probe_results = [
        ProbeResult(
            label="captured", status=f.response_status,
            headers=f.response_headers, body=f.response_body,
            elapsed_ms=0.0, error=None,
        )
        for f in flows
    ]
    vendors = match_vendors(probe_results, load_signatures())

    report = generate_report(
        domain=domain, flows=flows, session_stats=session_stats,
        vendors=vendors, auth_patterns=auth_patterns, cookies=cookies,
    )
    (dst_path / "report.md").write_text(report)

    for name in ("session.json", "graphql-schema.json"):
        src_file = src_path / name
        if src_file.exists():
            shutil.copy2(src_file, dst_path / name)

    return {
        "flows_processed": len(flows),
        "api_flows": len(api_flows),
        "endpoints": len(inventory),
        "paths": len(spec.get("paths", {})),
    }

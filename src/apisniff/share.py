from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

import yaml

from apisniff.auth import ExtractedCookie, detect_auth, extract_cookies
from apisniff.bundle import read_capture_jsonl
from apisniff.models import CapturedFlow, SessionStats, normalize_path
from apisniff.report import generate_report
from apisniff.spec import generate_openapi, is_api_flow
from apisniff.vendors import flows_to_probe_results, load_signatures, match_vendors


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

    flows_path = src_path / "flows.jsonl"
    if not flows_path.exists():
        raise FileNotFoundError(f"No flows.jsonl in {src_path}")
    flows = read_capture_jsonl(str(flows_path))

    dst_path.mkdir(parents=True, exist_ok=True)

    api_flows = [f for f in flows if is_api_flow(f)]
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

    vendors = match_vendors(flows_to_probe_results(flows), load_signatures())

    safe_cookies = [
        ExtractedCookie(
            name=c.name, value="[redacted]", domain=c.domain,
            host_only=c.host_only, path=c.path, secure=c.secure, source=c.source
        )
        for c in cookies
    ]

    report = generate_report(
        domain=domain, flows=flows, session_stats=session_stats,
        vendors=vendors, auth_patterns=auth_patterns, cookies=safe_cookies,
    )
    (dst_path / "report.md").write_text(report)

    if session_stats:
        safe_session = {
            "domain": session_stats.domain,
            "started_at": session_stats.started_at,
            "duration_seconds": session_stats.duration_seconds,
            "total_flows": session_stats.total_flows,
            "kept_flows": session_stats.kept_flows,
            "dropped": dict(session_stats.dropped),
        }
        (dst_path / "session.json").write_text(json.dumps(safe_session, indent=2))

    gql_src = src_path / "graphql-schema.json"
    if gql_src.exists():
        shutil.copy2(gql_src, dst_path / "graphql-schema.json")

    return {
        "flows_processed": len(flows),
        "api_flows": len(api_flows),
        "endpoints": len(inventory),
        "paths": len(spec.get("paths", {})),
    }

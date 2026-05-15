from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from apisniff.auth import ExtractedCookie, detect_auth, extract_cookies
from apisniff.bundle import read_capture_jsonl
from apisniff.models import SessionStats
from apisniff.report import generate_report
from apisniff.spec import build_surface_inventory, generate_openapi
from apisniff.spec_classify import classify_flows, select_openapi_flow
from apisniff.vendors import flows_to_probe_results, load_signatures, match_vendors


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
    classifications = classify_flows(flows, domain)

    dst_path.mkdir(parents=True, exist_ok=True)

    api_flows = [
        flow
        for flow, classification in zip(flows, classifications, strict=True)
        if select_openapi_flow(flow, classification, domain)
    ]
    auth_patterns = detect_auth(api_flows)
    cookies = extract_cookies(flows)

    spec = generate_openapi(
        api_flows, domain, auth_patterns=auth_patterns,
        infer_schemes=True, include_examples=False,
    )
    spec_yaml = yaml.dump(spec, sort_keys=False, default_flow_style=False)
    (dst_path / "spec.yaml").write_text(spec_yaml)

    inventory = build_surface_inventory(flows, domain, classifications)
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
        for field in (
            "captured_flows",
            "openapi_candidate_flows",
            "surface_flows",
            "noise_flows",
        ):
            value = getattr(session_stats, field)
            if value is not None:
                safe_session[field] = value
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

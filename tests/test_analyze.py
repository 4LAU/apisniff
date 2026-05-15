# tests/test_analyze.py
"""End-to-end tests for run_analyze() and the 'analyze' CLI command."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apisniff.bundle import MAX_IMPORT_BYTES
from apisniff.cli import app
from apisniff.models import CapturedFlow
from apisniff.recon import run_analyze, write_flow_jsonl

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_har(entries: list[dict]) -> str:
    return json.dumps({"log": {"entries": entries}})


def _har_entry(
    *,
    url: str = "https://api.example.com/v1/items",
    method: str = "GET",
    status: int = 200,
    resp_body: str = '{"items":[]}',
    resp_ct: str = "application/json",
) -> dict:
    return {
        "startedDateTime": "2024-01-01T00:00:00Z",
        "request": {
            "method": method,
            "url": url,
            "headers": [{"name": "user-agent", "value": "pytest"}],
        },
        "response": {
            "status": status,
            "headers": [{"name": "content-type", "value": resp_ct}],
            "content": {"text": resp_body, "mimeType": resp_ct},
        },
    }


runner = CliRunner()


# ---------------------------------------------------------------------------
# run_analyze() with a HAR input
# ---------------------------------------------------------------------------

def test_run_analyze_har_creates_bundle(tmp_path: Path) -> None:
    """HAR input produces a readable bundle with the expected domain and flow."""
    har_text = _make_har([
        _har_entry(url="https://api.example.com/v1/users"),
        _har_entry(url="https://api.example.com/v1/items", method="POST", status=201),
    ])
    har_file = tmp_path / "traffic.har"
    har_file.write_text(har_text)

    bundle_dir = tmp_path / "bundle"

    run_analyze(
        str(har_file),
        domain="example.com",
        output_dir=str(bundle_dir),
    )

    assert (bundle_dir / "flows.jsonl").exists(), "flows.jsonl missing"
    assert (bundle_dir / "session.json").exists(), "session.json missing"
    assert (bundle_dir / "report.md").exists(), "report.md missing"
    lines = (bundle_dir / "flows.jsonl").read_text().strip().splitlines()
    flow_dict = json.loads(lines[0])
    sess = json.loads((bundle_dir / "session.json").read_text())
    assert sess["domain"] == "example.com"
    assert flow_dict["host"] == "api.example.com"
    assert flow_dict["method"] == "GET"


# ---------------------------------------------------------------------------
# Domain auto-detection
# ---------------------------------------------------------------------------

def test_run_analyze_auto_detect_domain(tmp_path: Path) -> None:
    """Domain is auto-detected from the most common registered domain in flows."""
    har_text = _make_har([
        _har_entry(url="https://api.mysite.com/v1/users"),
        _har_entry(url="https://api.mysite.com/v1/items"),
        _har_entry(url="https://cdn.mysite.com/asset.png", resp_ct="image/png"),
    ])
    har_file = tmp_path / "traffic.har"
    har_file.write_text(har_text)

    bundle_dir = tmp_path / "bundle"
    # No domain argument — must auto-detect
    run_analyze(str(har_file), output_dir=str(bundle_dir))

    sess = json.loads((bundle_dir / "session.json").read_text())
    assert sess["domain"] == "mysite.com"


def test_run_analyze_auto_detect_warns_ambiguous(
    tmp_path: Path, capfd: pytest.CaptureFixture
) -> None:
    """Ambiguous domain triggers a warning (stderr) but does not abort."""
    # Two equally-common domains → should warn
    har_text = _make_har([
        _har_entry(url="https://api.aaa.com/v1/x"),
        _har_entry(url="https://api.bbb.com/v1/x"),
    ])
    har_file = tmp_path / "traffic.har"
    har_file.write_text(har_text)

    bundle_dir = tmp_path / "bundle"
    # Should not raise even when ambiguous
    run_analyze(str(har_file), output_dir=str(bundle_dir))

    captured = capfd.readouterr()
    assert "ambiguous" in captured.err.lower()

    # bundle should still be created
    assert (bundle_dir / "session.json").exists()


# ---------------------------------------------------------------------------
# JSONL input skips classification
# ---------------------------------------------------------------------------

def test_run_analyze_jsonl_skips_classification(tmp_path: Path) -> None:
    """JSONL input passes all flows through without running the Classifier."""
    flow = CapturedFlow(
        method="GET",
        host="api.example.com",
        path="/v1/items",
        url="https://api.example.com/v1/items",
        request_headers={"user-agent": "pytest"},
        request_body=b"",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"items":[]}',
        tags=["api_signal"],
        timestamp=1715100000.0,
    )
    jsonl_file = tmp_path / "flows.jsonl"
    with open(jsonl_file, "w") as fh:
        write_flow_jsonl(fh, flow)

    bundle_dir = tmp_path / "bundle"
    run_analyze(str(jsonl_file), domain="example.com", output_dir=str(bundle_dir))

    sess = json.loads((bundle_dir / "session.json").read_text())
    # For JSONL: kept_flows == total_flows (no drops from classification)
    assert sess["kept_flows"] == sess["total_flows"]
    assert sess["dropped"] == {}

    lines = (bundle_dir / "flows.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1


def test_run_analyze_json_output_is_llm_optimized(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    flows = [
        CapturedFlow(
            method="GET",
            host="api.example.com",
            path="/api/users/123",
            url="https://api.example.com/api/users/123",
            request_headers={
                "authorization": "Bearer token",
                "cookie": "sessionid=abc",
            },
            request_body=b"",
            response_status=200,
            response_headers={
                "content-type": "application/json",
                "cf-mitigated": "challenge",
                "set-cookie": "sessionid=abc; Path=/; Secure",
            },
            response_body=b'{"id":123}',
            tags=["api_signal"],
            timestamp=1715100000.0,
        ),
        CapturedFlow(
            method="GET",
            host="api.example.com",
            path="/api/users/456?include=profile",
            url="https://api.example.com/api/users/456?include=profile",
            request_headers={"authorization": "Bearer token"},
            request_body=b"",
            response_status=200,
            response_headers={"content-type": "application/json"},
            response_body=b'{"id":456}',
            tags=["api_signal"],
            timestamp=1715100001.0,
        ),
    ]
    jsonl_file = tmp_path / "flows.jsonl"
    with open(jsonl_file, "w") as fh:
        for flow in flows:
            write_flow_jsonl(fh, flow)

    bundle_dir = tmp_path / "bundle"
    run_analyze(
        str(jsonl_file),
        domain="example.com",
        json_output=True,
        output_dir=str(bundle_dir),
    )

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert data["schema_version"] == 1
    assert "Analyzed 2 flows for example.com" in data["interpretation"]
    assert data["domain"] == "example.com"
    assert data["total_flows"] == 2
    assert data["kept_flows"] == 2
    assert data["drop_descriptions"]["static_asset"].startswith("Static files")
    assert data["auth_type_descriptions"]["bearer"].startswith("OAuth2")
    assert data["vendors"] == [
        {
            "vendor": "cloudflare",
            "confidence": "high",
            "signals": ["header_value:cf-mitigated"],
        }
    ]
    assert data["auth_patterns"] == [
        {
            "auth_type": "bearer",
            "detail": "authorization: bearer",
            "flow_count": 2,
        },
        {"auth_type": "session_cookie", "detail": "sessionid", "flow_count": 1},
    ]
    assert data["top_endpoints"] == [
        {"method": "GET", "path": "/api/users/{id}", "count": 2}
    ]
    assert data["bundle_dir"] == str(bundle_dir)
    assert data["report_path"] == str(bundle_dir / "report.md")
    assert data["cookies_path"] == str(bundle_dir / "cookies.txt")
    assert data["graphql_schema_path"] is None


# ---------------------------------------------------------------------------
# HAR with static-asset drops (classification reduces flow count)
# ---------------------------------------------------------------------------

def test_run_analyze_har_classifies_drops_static(tmp_path: Path) -> None:
    """Classifier drops static assets; kept_flows < total_flows for HAR."""
    har_text = _make_har([
        _har_entry(url="https://api.example.com/v1/users"),
        _har_entry(url="https://api.example.com/app.js", resp_ct="application/javascript"),
        _har_entry(url="https://api.example.com/style.css", resp_ct="text/css"),
    ])
    har_file = tmp_path / "traffic.har"
    har_file.write_text(har_text)

    bundle_dir = tmp_path / "bundle"
    run_analyze(str(har_file), domain="example.com", output_dir=str(bundle_dir))

    sess = json.loads((bundle_dir / "session.json").read_text())
    assert sess["total_flows"] == 3
    assert sess["kept_flows"] < sess["total_flows"]


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

def test_cli_analyze_command(tmp_path: Path) -> None:
    """'apisniff analyze' command exits 0 and creates expected files."""
    har_text = _make_har([_har_entry(url="https://api.example.com/v1/users")])
    har_file = tmp_path / "traffic.har"
    har_file.write_text(har_text)

    bundle_dir = tmp_path / "bundle"

    result = runner.invoke(app, [
        "analyze", str(har_file),
        "--domain", "example.com",
        "--output-dir", str(bundle_dir),
    ])

    assert result.exit_code == 0, f"Non-zero exit: {result.output}"
    assert (bundle_dir / "flows.jsonl").exists()
    assert (bundle_dir / "session.json").exists()
    assert (bundle_dir / "report.md").exists()


def test_cli_analyze_oversized_input_exits_without_traceback(tmp_path: Path) -> None:
    har_file = tmp_path / "large.har"
    with har_file.open("wb") as f:
        f.truncate(MAX_IMPORT_BYTES + 1)

    result = runner.invoke(app, ["analyze", str(har_file), "--domain", "example.com"])

    assert result.exit_code == 1
    assert "Input file is too large" in result.output
    assert "Traceback" not in result.output

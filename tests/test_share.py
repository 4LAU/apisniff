import json
from dataclasses import replace

import yaml
from typer.testing import CliRunner

from apisniff.cli import app
from apisniff.models import CapturedFlow
from apisniff.share import share_bundle

runner = CliRunner()


def _flow(
    method="GET",
    path="/api/users",
    request_headers=None,
    request_body=b"",
    response_status=200,
    response_headers=None,
    response_body=b'{"ok": true}',
):
    if response_headers is None:
        response_headers = {"content-type": "application/json"}
    if request_headers is None:
        request_headers = {}
    return CapturedFlow(
        method=method,
        host="example.com",
        path=path,
        url=f"https://example.com{path}",
        request_headers=request_headers,
        request_body=request_body,
        response_status=response_status,
        response_headers=response_headers,
        response_body=response_body,
    )


def _write_bundle(tmp_path, flows, extras=None):
    """Write a minimal source bundle to tmp_path."""
    src = tmp_path / "bundle"
    src.mkdir()
    lines = [f.to_jsonl() for f in flows]
    (src / "flows.jsonl").write_text("\n".join(lines) + "\n")
    session_data = {
        "domain": "example.com",
        "started_at": "2025-01-01T00:00:00Z",
        "duration_seconds": 60.0,
        "total_flows": len(flows),
        "kept_flows": len(flows),
        "dropped": {},
    }
    (src / "session.json").write_text(json.dumps(session_data))
    (src / "report.md").write_text("# example.com\n")
    if extras:
        for name, content in extras.items():
            (src / name).write_text(content)
    return src


# ---------------------------------------------------------------------------
# share_bundle tests
# ---------------------------------------------------------------------------


def test_share_bundle_creates_derived_output(tmp_path):
    """Share produces spec, inventory, session, report — no flows.jsonl."""
    src = _write_bundle(tmp_path, [_flow()])
    dst = tmp_path / "shared"

    share_bundle(str(src), str(dst), "example.com")

    assert (dst / "spec.yaml").exists()
    assert (dst / "inventory.json").exists()
    assert (dst / "session.json").exists()
    assert (dst / "report.md").exists()
    assert not (dst / "flows.jsonl").exists()
    assert not (dst / "cookies.txt").exists()


def test_share_bundle_no_raw_secrets_in_output(tmp_path):
    """No auth headers, query params, or body secrets leak into shared output."""
    flow = _flow(
        path="/api/users?api_key=secret_key_999",
        request_headers={
            "authorization": "Bearer sk_live_secret",
            "cookie": "session=abc123",
            "accept": "application/json",
        },
        request_body=b'{"password": "hunter2", "email": "user@private.com"}',
        response_body=(
            b'{"token": "eyJhbGciOiJSUzI1NiJ9.payload", '
            b'"ssn": "123-45-6789", '
            b'"email": "alice@example.com", '
            b'"session_id": "session_id_abc123"}'
        ),
    )
    flow = replace(flow, tags=["token=tag_secret_999", "surface:business_api"])
    src = _write_bundle(tmp_path, [flow])
    dst = tmp_path / "shared"

    share_bundle(str(src), str(dst), "example.com")

    for p in dst.iterdir():
        content = p.read_text()
        assert "sk_live_secret" not in content
        assert "session=abc123" not in content
        assert "abc123" not in content
        assert "secret_key_999" not in content
        assert "hunter2" not in content
        assert "eyJhbGciOiJSUzI1NiJ9" not in content
        assert "123-45-6789" not in content
        assert "alice@example.com" not in content
        assert "session_id_abc123" not in content
        assert "tag_secret_999" not in content


def test_share_bundle_spec_has_no_examples(tmp_path):
    """Share spec omits examples so arbitrary captured values cannot leak."""
    flow = _flow(response_body=b'{"email": "alice@example.com", "name": "Alice"}')
    src = _write_bundle(tmp_path, [flow])
    dst = tmp_path / "shared"

    share_bundle(str(src), str(dst), "example.com")

    spec = yaml.safe_load((dst / "spec.yaml").read_text())
    props = spec["paths"]["/api/users"]["get"]["responses"]["200"]
    schema_props = props["content"]["application/json"]["schema"]["properties"]
    assert "example" not in schema_props["email"]
    assert "example" not in schema_props["name"]


def test_share_bundle_inventory_includes_operational_flows_excluded_from_spec(tmp_path):
    business = _flow(path="/api/users")
    antibot = _flow(
        method="POST",
        path="/jMdNhK4DL/bTQsJS7e/Q/XNYrQm1k/Mn1tPnsWAg/bxM/MaQZNbw4u",
        request_headers={"content-type": "text/plain;charset=UTF-8"},
        request_body=b'{"sensor_data":"3;0;1"}',
    )
    src = _write_bundle(tmp_path, [business, antibot])
    dst = tmp_path / "shared"

    share_bundle(str(src), str(dst), "example.com")

    spec = yaml.safe_load((dst / "spec.yaml").read_text())
    assert "/api/users" in spec["paths"]
    assert "/jMdNhK4DL/bTQsJS7e/Q/XNYrQm1k/Mn1tPnsWAg/bxM/MaQZNbw4u" not in spec["paths"]

    inventory = json.loads((dst / "inventory.json").read_text())
    categories = {entry["category"]: entry for entry in inventory}
    assert categories["business_api"]["included_in_openapi"] is True
    assert categories["antibot"]["included_in_openapi"] is False


def test_share_bundle_regenerates_report(tmp_path):
    """Report is regenerated, not copied — stale source report is ignored."""
    src = _write_bundle(tmp_path, [_flow()])
    (src / "report.md").write_text(
        "# Stale report\n- `sid` = `leaked_cookie_value`\n"
    )
    dst = tmp_path / "shared"

    share_bundle(str(src), str(dst), "example.com")

    report = (dst / "report.md").read_text()
    assert "leaked_cookie_value" not in report
    assert "example.com" in report


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


def test_cli_share_command(tmp_path):
    """CLI share command produces derived output."""
    src = _write_bundle(tmp_path, [_flow()])
    dst = tmp_path / "output"

    result = runner.invoke(
        app, ["share", str(src), "--output", str(dst), "--domain", "example.com"]
    )
    assert result.exit_code == 0
    assert (dst / "spec.yaml").exists()
    assert (dst / "inventory.json").exists()
    assert not (dst / "flows.jsonl").exists()


def test_cli_share_refuses_existing_output(tmp_path):
    """CLI refuses to overwrite existing output directory."""
    src = _write_bundle(tmp_path, [_flow()])
    dst = tmp_path / "output"
    dst.mkdir()

    result = runner.invoke(
        app, ["share", str(src), "--output", str(dst), "--domain", "example.com"]
    )
    assert result.exit_code == 1

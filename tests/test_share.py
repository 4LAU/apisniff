import json

import yaml
from typer.testing import CliRunner

from apisniff.cli import app
from apisniff.models import CapturedFlow
from apisniff.share import generate_inventory, share_bundle

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
# generate_inventory tests
# ---------------------------------------------------------------------------


def test_generate_inventory_groups_by_endpoint():
    """Inventory groups flows by normalized path + method."""
    flows = [
        _flow("GET", "/api/users"),
        _flow("GET", "/api/users"),
        _flow("GET", "/api/users/123"),
        _flow("POST", "/api/users"),
    ]
    inventory = generate_inventory(flows)
    assert len(inventory) == 3
    get_users = next(
        e for e in inventory
        if e["method"] == "GET" and e["path"] == "/api/users"
    )
    assert get_users["count"] == 2
    get_user_id = next(
        e for e in inventory
        if e["path"] == "/api/users/{id}"
    )
    assert get_user_id["method"] == "GET"
    assert get_user_id["count"] == 1


def test_generate_inventory_captures_status_codes():
    """Inventory records all observed status codes."""
    flows = [
        _flow("GET", "/api/users", response_status=200),
        _flow("GET", "/api/users", response_status=200),
        _flow("GET", "/api/users", response_status=404),
    ]
    inventory = generate_inventory(flows)
    entry = inventory[0]
    assert set(entry["status_codes"]) == {200, 404}


def test_generate_inventory_captures_content_types():
    """Inventory records response content types."""
    flows = [
        _flow(
            "GET", "/api/users",
            response_headers={"content-type": "application/json"},
        ),
        _flow(
            "GET", "/api/users",
            response_headers={"content-type": "text/html"},
        ),
    ]
    inventory = generate_inventory(flows)
    entry = inventory[0]
    assert "application/json" in entry["content_types"]
    assert "text/html" in entry["content_types"]


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

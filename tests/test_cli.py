# tests/test_cli.py
import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

import apisniff.probe
from apisniff.cli import _parse_header_args, _parse_probe_target, app
from apisniff.models import CapturedFlow

runner = CliRunner()


def _write_spec_input(path: Path) -> None:
    flow = CapturedFlow(
        method="GET",
        host="api.example.com",
        path="/v1/users/123",
        url="https://api.example.com/v1/users/123",
        request_headers={"authorization": "bearer test-token"},
        request_body=b"",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"id": 123, "name": "Alice", "token": "sk_live_secret"}',
    )
    path.write_text(flow.to_jsonl() + "\n")


def _write_graphql_input(path: Path) -> None:
    flow = CapturedFlow(
        method="POST",
        host="api.example.com",
        path="/graphql",
        url="https://api.example.com/graphql",
        request_headers={
            "authorization": "bearer captured-token",
            "content-type": "application/json",
        },
        request_body=b'{"query":"{ viewer { id } }"}',
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"data":{"viewer":{"id":"u_123"}}}',
    )
    path.write_text(flow.to_jsonl() + "\n")


def test_probe_help():
    result = runner.invoke(app, ["probe", "--help"])
    assert result.exit_code == 0
    assert "defense preflight" in result.output.lower() or "url" in result.output.lower()
    assert "--probe-rate" not in result.output
    assert "--impersonate" not in result.output


def test_main_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "probe" in result.output
    assert "recon" in result.output
    assert "spec" in result.output


def test_parse_header_valid():
    result = _parse_header_args(["Authorization: Bearer tok123", "X-Custom:val"])
    assert result == {"Authorization": "Bearer tok123", "X-Custom": "val"}


def test_parse_probe_target_default_probe():
    assert _parse_probe_target(["example.com"]) == ("example.com", False)


def test_parse_probe_target_rate_probe():
    assert _parse_probe_target(["rate", "example.com"]) == ("example.com", True)


def test_parse_probe_target_rate_requires_url():
    with pytest.raises(typer.BadParameter, match="apisniff probe rate URL"):
        _parse_probe_target(["rate"])


def test_spec_cli_uses_opinionated_defaults(tmp_path: Path):
    input_file = tmp_path / "flows.jsonl"
    output_file = tmp_path / "spec.json"
    _write_spec_input(input_file)

    result = runner.invoke(
        app,
        ["spec", "example.com", "-i", str(input_file), "-f", "json", "-o", str(output_file)],
    )

    assert result.exit_code == 0
    spec = json.loads(output_file.read_text())
    user_schema = (
        spec["paths"]["/v1/users/{id}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]
    )
    assert user_schema["properties"]["id"]["example"] == 123
    assert user_schema["properties"]["token"]["example"] == "***REDACTED***"
    assert spec["components"]["securitySchemes"]["bearer"] == {
        "type": "http",
        "scheme": "bearer",
    }


def test_spec_cli_can_omit_examples(tmp_path: Path):
    input_file = tmp_path / "flows.jsonl"
    output_file = tmp_path / "spec.json"
    _write_spec_input(input_file)

    result = runner.invoke(
        app,
        [
            "spec",
            "example.com",
            "-i",
            str(input_file),
            "-f",
            "json",
            "-o",
            str(output_file),
            "--no-examples",
        ],
    )

    assert result.exit_code == 0
    spec = json.loads(output_file.read_text())
    user_schema = (
        spec["paths"]["/v1/users/{id}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]
    )
    assert "example" not in user_schema["properties"]["id"]
    assert "example" not in user_schema["properties"]["token"]


def test_analyze_cli_does_not_fetch_graphql_by_default(monkeypatch, tmp_path: Path):
    input_file = tmp_path / "flows.jsonl"
    output_dir = tmp_path / "bundle"
    _write_graphql_input(input_file)
    client_calls = []

    class RecordingClient:
        def __init__(self, *args, **kwargs):
            client_calls.append((args, kwargs))

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            raise AssertionError("GraphQL fetch should be opt-in")

    monkeypatch.setattr(apisniff.probe.httpx, "AsyncClient", RecordingClient)

    result = runner.invoke(
        app,
        [
            "analyze",
            str(input_file),
            "--domain",
            "example.com",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert client_calls == []

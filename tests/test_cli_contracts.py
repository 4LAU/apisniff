# tests/test_cli_contracts.py
"""CLI wire contracts — flags that silently produce wrong output if broken.

Each test protects a flag/mode whose failure would NOT crash the CLI but
would silently produce incorrect, missing, or leaked data.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml
from typer.testing import CliRunner

from apisniff.cli import app

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"


def _extract_json(output: str) -> dict:
    idx = output.find("{")
    assert idx != -1, f"No JSON found in output: {output[:200]}"
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(output, idx)
    return obj


def _extract_yaml(output: str) -> dict:
    lines = output.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith("openapi:"):
            start = i
            break
    assert start is not None, f"No YAML spec found in output: {output[:300]}"
    yaml_text = "\n".join(lines[start:])
    return yaml.safe_load(yaml_text)


def _create_bundle(tmp_path: Path, fixture: str = "minimal.har") -> Path:
    bundle_dir = tmp_path / "bundle"
    result = runner.invoke(app, [
        "analyze", str(FIXTURES / fixture),
        "--output-dir", str(bundle_dir),
    ])
    assert result.exit_code == 0, f"analyze failed: {result.output}"
    return bundle_dir


# --- analyze: silent-failure flags ---


class TestAnalyzeDomain:
    def test_domain_override(self, tmp_path: Path):
        """--domain could silently be ignored; session.json would have wrong domain."""
        bundle = tmp_path / "out"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "minimal.har"),
            "--domain", "custom.example.org",
            "--output-dir", str(bundle),
        ])
        assert result.exit_code == 0
        session = json.loads((bundle / "session.json").read_text())
        assert session["domain"] == "custom.example.org"


class TestAnalyzeJSON:
    def test_json_flag(self, tmp_path: Path):
        """--json could silently produce non-JSON output."""
        bundle = tmp_path / "out"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "minimal.har"),
            "--json", "--output-dir", str(bundle),
        ])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert "domain" in data
        assert "total_flows" in data
        assert "kept_flows" in data


# --- spec: silent-failure flags ---


class TestSpecFormats:
    def test_default_yaml_to_stdout(self, tmp_path: Path):
        """Spec YAML could silently be invalid OpenAPI."""
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
        ])
        assert result.exit_code == 0
        spec = _extract_yaml(result.output)
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec

    def test_format_json(self, tmp_path: Path):
        """--format json could silently produce invalid JSON."""
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec

    def test_output_file(self, tmp_path: Path):
        """--output could silently not write the file."""
        bundle = _create_bundle(tmp_path)
        out_file = tmp_path / "spec.yaml"
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--output", str(out_file),
        ])
        assert result.exit_code == 0
        assert out_file.exists()
        spec = yaml.safe_load(out_file.read_text())
        assert "paths" in spec


class TestSpecExamples:
    def test_examples_flag(self, tmp_path: Path):
        """--examples could silently be ignored, producing no example keys."""
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json", "--examples",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        raw = json.dumps(spec)
        assert "example" in raw.lower(), "Expected at least one 'example' key in spec"

    def test_examples_no_secrets(self, tmp_path: Path):
        """Tier 1 security: --examples must not leak captured secrets."""
        bundle = tmp_path / "out"
        runner.invoke(app, [
            "analyze", str(FIXTURES / "redaction.jsonl"),
            "--output-dir", str(bundle),
        ])
        spec_result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json", "--examples",
        ])
        assert spec_result.exit_code == 0
        output = spec_result.output
        for pattern in ("sk_live_", "SuperSecret", "hunter2"):
            assert pattern not in output, f"Secret pattern {pattern!r} found in spec"


class TestSpecInclusion:
    def test_include_third_party(self, tmp_path: Path):
        """--include-third-party could silently still exclude third-party paths."""
        bundle = _create_bundle(tmp_path, "multisite.har")
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json", "--include-third-party",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        paths = list(spec.get("paths", {}).keys())
        assert len(paths) > 0, "Expected third-party paths in spec"

    def test_include_host(self, tmp_path: Path):
        """--include-host could silently be ignored."""
        bundle = _create_bundle(tmp_path, "multisite.har")
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json",
            "--include-host", "api.stripe.com",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        paths_str = json.dumps(spec.get("paths", {}))
        assert "charges" in paths_str, "Expected api.stripe.com paths with --include-host"

    def test_no_infer_security_schemes(self, tmp_path: Path):
        """--no-infer-security-schemes could silently still emit securitySchemes."""
        bundle = _create_bundle(tmp_path, "auth_variants.har")
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json", "--no-infer-security-schemes",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        components = spec.get("components", {})
        assert "securitySchemes" not in components


# --- replay: silent-failure flags ---


class TestReplayDryRun:
    def test_json_output(self, tmp_path: Path):
        """--dry-run --json could silently produce non-JSON."""
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "replay", str(bundle), "--dry-run", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "endpoints" in data

    def test_filter_pattern(self, tmp_path: Path):
        """--filter could silently include non-matching paths."""
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "replay", str(bundle), "--dry-run", "--json",
            "--filter", "/api/*",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        for ep in data["endpoints"]:
            assert ep["path"].startswith("/api/"), (
                f"Endpoint {ep['path']} does not match filter /api/*"
            )

    def test_include_unsafe(self, tmp_path: Path):
        """--include-unsafe could silently still exclude POST/PUT."""
        bundle = _create_bundle(tmp_path)
        result_safe = runner.invoke(app, [
            "replay", str(bundle), "--dry-run", "--json",
        ])
        result_unsafe = runner.invoke(app, [
            "replay", str(bundle), "--dry-run", "--json", "--include-unsafe",
        ])
        assert result_safe.exit_code == 0
        assert result_unsafe.exit_code == 0
        safe_data = json.loads(result_safe.output)
        unsafe_data = json.loads(result_unsafe.output)
        safe_eps = len(safe_data["endpoints"])
        unsafe_eps = len(unsafe_data["endpoints"])
        assert unsafe_eps >= safe_eps


# --- share: security invariants ---


class TestShare:
    def test_spec_yaml_valid_openapi(self, tmp_path: Path):
        """Shared spec.yaml could silently be invalid OpenAPI."""
        bundle = _create_bundle(tmp_path)
        share_out = tmp_path / "shared"
        runner.invoke(app, ["share", str(bundle), "--output", str(share_out)])
        spec = yaml.safe_load((share_out / "spec.yaml").read_text())
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec

    def test_no_raw_traffic(self, tmp_path: Path):
        """Tier 1 security: shared bundle must not contain raw request/response bodies."""
        bundle = _create_bundle(tmp_path)
        share_out = tmp_path / "shared"
        runner.invoke(app, ["share", str(bundle), "--output", str(share_out)])
        for json_file in share_out.glob("*.json"):
            content = json_file.read_text()
            assert "request_body" not in content, f"request_body in {json_file.name}"
            assert "response_body" not in content, f"response_body in {json_file.name}"

    def test_no_secrets_in_output(self, tmp_path: Path):
        """Tier 1 security: shared bundle must not leak secrets."""
        bundle = tmp_path / "bundle"
        runner.invoke(app, [
            "analyze", str(FIXTURES / "redaction.jsonl"),
            "--output-dir", str(bundle),
        ])
        share_out = tmp_path / "shared"
        runner.invoke(app, ["share", str(bundle), "--output", str(share_out)])
        for f in share_out.iterdir():
            if f.is_file():
                content = f.read_text()
                for pattern in ("sk_live_", "SuperSecret", "hunter2"):
                    assert pattern not in content, f"Secret {pattern!r} in {f.name}"


# --- probe: exit code contracts ---


class TestProbe:
    def _mock_assessment(self, verdict_value):
        from apisniff.models import ProbeAssessment, ProbeResult, ProbeVerdict
        verdict = ProbeVerdict(verdict_value)
        dummy = ProbeResult(
            label="naked", status=200, headers={}, body=b"ok",
            elapsed_ms=50.0, error=None,
        )
        return ProbeAssessment(
            url="https://example.com",
            verdict=verdict,
            recommendation="Test",
            results={"naked": dummy, "impersonated": dummy, "tls_only": dummy},
            vendors=[],
        )

    def test_json_output_shape(self):
        """--json could silently produce wrong shape."""
        assessment = self._mock_assessment("no_protection")
        with patch("apisniff.probe.run_probes", new_callable=AsyncMock, return_value=assessment):
            result = runner.invoke(app, ["probe", "example.com", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "verdict" in data
        assert "probes" in data
        assert "url" in data

    def test_exit_code_2_on_full_block(self):
        """Exit code 2 on FULL_BLOCK could silently become 0."""
        assessment = self._mock_assessment("full_block")
        with patch("apisniff.probe.run_probes", new_callable=AsyncMock, return_value=assessment):
            result = runner.invoke(app, ["probe", "example.com", "--json"])
        assert result.exit_code == 2

    def test_exit_code_0_on_no_protection(self):
        """Exit code on NO_PROTECTION could silently be non-zero."""
        assessment = self._mock_assessment("no_protection")
        with patch("apisniff.probe.run_probes", new_callable=AsyncMock, return_value=assessment):
            result = runner.invoke(app, ["probe", "example.com", "--json"])
        assert result.exit_code == 0

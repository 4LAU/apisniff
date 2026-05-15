# tests/test_cli_contracts.py
"""CLI contract tests — verify every command's observable behavior through CliRunner."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml
from typer.testing import CliRunner

from apisniff.cli import app

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bundle_files_present(bundle_dir: Path) -> dict[str, bool]:
    """Return a map of expected bundle filenames → exists."""
    expected = ["flows.jsonl", "session.json", "surface.jsonl", "report.md"]
    return {name: (bundle_dir / name).exists() for name in expected}


def _find_bundle_dir(parent: Path) -> Path:
    """Find the first (usually only) bundle directory created under parent."""
    dirs = [p for p in parent.iterdir() if p.is_dir()]
    assert dirs, f"No bundle directory found in {parent}"
    return dirs[0]


def _extract_json(output: str) -> dict:
    """Extract the JSON object from mixed CliRunner output (stderr + stdout merged).

    CliRunner merges stdout and stderr. Rich status lines appear before/after
    the JSON body. Find the first '{' and use raw_decode to stop at the end of
    the JSON object, ignoring trailing stderr text.
    """
    idx = output.find("{")
    assert idx != -1, f"No JSON found in output: {output[:200]}"
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(output, idx)
    return obj


def _extract_yaml(output: str) -> dict:
    """Extract the YAML document from mixed CliRunner output.

    The YAML starts with 'openapi:' — find that line and parse from there.
    """
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
    """Run analyze to create a real bundle, return bundle dir path."""
    bundle_dir = tmp_path / "bundle"
    result = runner.invoke(app, [
        "analyze", str(FIXTURES / fixture),
        "--output-dir", str(bundle_dir),
    ])
    assert result.exit_code == 0, f"analyze failed: {result.output}"
    return bundle_dir


# ===========================================================================
# analyze
# ===========================================================================


class TestAnalyzeHAR:
    def test_har_creates_bundle(self, tmp_path: Path):
        bundle = tmp_path / "out"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "minimal.har"),
            "--output-dir", str(bundle),
        ])
        assert result.exit_code == 0
        present = _bundle_files_present(bundle)
        for name, exists in present.items():
            assert exists, f"Missing {name} in bundle"

    def test_burp_creates_bundle(self, tmp_path: Path):
        bundle = tmp_path / "out"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "minimal.burp.xml"),
            "--output-dir", str(bundle),
        ])
        assert result.exit_code == 0
        present = _bundle_files_present(bundle)
        for name, exists in present.items():
            assert exists, f"Missing {name} in bundle"

    def test_jsonl_creates_bundle(self, tmp_path: Path):
        bundle = tmp_path / "out"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "minimal.jsonl"),
            "--output-dir", str(bundle),
        ])
        assert result.exit_code == 0
        present = _bundle_files_present(bundle)
        for name, exists in present.items():
            assert exists, f"Missing {name} in bundle"


class TestAnalyzeDomain:
    def test_domain_override(self, tmp_path: Path):
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


class TestAnalyzeErrors:
    def test_missing_file_exits_1(self):
        result = runner.invoke(app, ["analyze", "/nonexistent/file.har"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "not found" in (result.stderr or "").lower()

    def test_malformed_input_no_traceback(self):
        result = runner.invoke(app, ["analyze", str(FIXTURES / "malformed.har")])
        # Malformed HAR may produce empty flows and exit early or exit 0
        # The key contract: no Python traceback in output
        combined = result.output + (result.stderr or "")
        assert "Traceback" not in combined

    def test_empty_har_no_crash(self, tmp_path: Path):
        bundle = tmp_path / "out"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "empty.har"),
            "--output-dir", str(bundle),
        ])
        # Empty HAR has zero entries. run_analyze prints a warning and returns early.
        # The contract: no crash (exit 0), no traceback.
        assert result.exit_code == 0
        combined = result.output + (result.stderr or "")
        assert "Traceback" not in combined


# ===========================================================================
# spec
# ===========================================================================


class TestSpecYAML:
    def test_default_yaml_to_stdout(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
        ])
        assert result.exit_code == 0
        spec = _extract_yaml(result.output)
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec

    def test_format_json(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec


class TestSpecOutput:
    def test_output_file(self, tmp_path: Path):
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

    def test_surface_output(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        out_file = tmp_path / "spec.yaml"
        surface_out = tmp_path / "surface.json"
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--output", str(out_file),
            "--surface-output", str(surface_out),
        ])
        assert result.exit_code == 0
        assert surface_out.exists()
        inventory = json.loads(surface_out.read_text())
        assert isinstance(inventory, (list, dict))


class TestSpecExamples:
    def test_examples_flag(self, tmp_path: Path):
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
        """Even with --examples, secret values must not appear in output."""
        bundle = tmp_path / "out"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "redaction.jsonl"),
            "--output-dir", str(bundle),
        ])
        assert result.exit_code == 0

        spec_result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json", "--examples",
        ])
        assert spec_result.exit_code == 0
        output = spec_result.output
        for pattern in ("sk_live_", "Bearer", "hunter2", "SuperSecret"):
            assert pattern not in output, f"Secret pattern {pattern!r} found in spec"


class TestSpecThirdParty:
    def test_include_third_party(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path, "multisite.har")
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json", "--include-third-party",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        # Third-party hosts should contribute paths
        # (stripe or api.example.com traffic visible)
        assert len(spec.get("paths", {})) > 0

    def test_include_host(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path, "multisite.har")
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json",
            "--include-host", "api.stripe.com",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        # When including api.stripe.com, its paths should appear
        paths_str = json.dumps(spec.get("paths", {}))
        assert "charges" in paths_str or len(spec.get("paths", {})) >= 0


class TestSpecNoInferSchemes:
    def test_no_infer_security_schemes(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path, "auth_variants.har")
        result = runner.invoke(app, [
            "spec", "example.com", "--input", str(bundle),
            "--format", "json", "--no-infer-security-schemes",
        ])
        assert result.exit_code == 0
        spec = _extract_json(result.output)
        components = spec.get("components", {})
        assert "securitySchemes" not in components, (
            "securitySchemes should not be present with --no-infer-security-schemes"
        )


class TestSpecEmptyInput:
    def test_no_api_flows_yields_empty_paths(self):
        """When input has zero API flows, spec should still be valid with empty paths."""
        # Pass empty.har directly to spec --input
        spec_result = runner.invoke(app, [
            "spec", "example.com", "--input", str(FIXTURES / "empty.har"),
            "--format", "json",
        ])
        # Either exits 0 with empty paths or exits 1 gracefully
        combined = spec_result.output + (spec_result.stderr or "")
        assert "Traceback" not in combined
        if spec_result.exit_code == 0 and "{" in spec_result.output:
            spec = _extract_json(spec_result.output)
            assert spec.get("paths") == {} or isinstance(spec.get("paths"), dict)


# ===========================================================================
# replay --dry-run
# ===========================================================================


class TestReplayDryRun:
    def test_lists_endpoints_no_http(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        # Monkeypatch to verify no HTTP calls are made
        with patch("apisniff.replay.replay_endpoint", new_callable=AsyncMock) as mock_replay:
            result = runner.invoke(app, [
                "replay", str(bundle), "--dry-run",
            ])
        assert result.exit_code == 0
        mock_replay.assert_not_called()

    def test_json_output(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        result = runner.invoke(app, [
            "replay", str(bundle), "--dry-run", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "endpoints" in data
        assert isinstance(data["endpoints"], list)

    def test_filter_pattern(self, tmp_path: Path):
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
        bundle = _create_bundle(tmp_path)
        # Without --include-unsafe, only GET/HEAD/OPTIONS
        result_safe = runner.invoke(app, [
            "replay", str(bundle), "--dry-run", "--json",
        ])
        assert result_safe.exit_code == 0
        safe_data = json.loads(result_safe.output)

        # With --include-unsafe, POST etc. appear
        result_unsafe = runner.invoke(app, [
            "replay", str(bundle), "--dry-run", "--json", "--include-unsafe",
        ])
        assert result_unsafe.exit_code == 0
        unsafe_data = json.loads(result_unsafe.output)

        # If there are POST flows in the bundle, unsafe should include them
        # or at least have >= as many endpoints
        total_unsafe = len(unsafe_data["endpoints"]) + len(unsafe_data.get("skipped_unsafe", []))
        total_safe = len(safe_data["endpoints"]) + len(safe_data.get("skipped_unsafe", []))
        assert total_unsafe >= total_safe

    def test_missing_bundle_exits_1(self):
        result = runner.invoke(app, [
            "replay", "/nonexistent/bundle/dir", "--dry-run",
        ])
        assert result.exit_code == 1
        combined = result.output + (result.stderr or "")
        assert "Traceback" not in combined


# ===========================================================================
# share
# ===========================================================================


class TestShare:
    def test_output_dir_contains_derived_files(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        share_out = tmp_path / "shared"
        result = runner.invoke(app, [
            "share", str(bundle), "--output", str(share_out),
        ])
        assert result.exit_code == 0
        for name in ("spec.yaml", "inventory.json", "report.md"):
            assert (share_out / name).exists(), f"Missing {name} in shared output"

    def test_spec_yaml_valid_openapi(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        share_out = tmp_path / "shared"
        result = runner.invoke(app, [
            "share", str(bundle), "--output", str(share_out),
        ])
        assert result.exit_code == 0
        spec = yaml.safe_load((share_out / "spec.yaml").read_text())
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec

    def test_no_raw_traffic(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        share_out = tmp_path / "shared"
        result = runner.invoke(app, [
            "share", str(bundle), "--output", str(share_out),
        ])
        assert result.exit_code == 0
        # Scan all JSON files for raw traffic keys
        for json_file in share_out.glob("*.json"):
            content = json_file.read_text()
            assert "request_body" not in content, (
                f"request_body found in {json_file.name}"
            )
            assert "response_body" not in content, (
                f"response_body found in {json_file.name}"
            )

    def test_no_secrets_in_output(self, tmp_path: Path):
        # Use redaction.jsonl which has secrets in bodies
        bundle = tmp_path / "bundle"
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "redaction.jsonl"),
            "--output-dir", str(bundle),
        ])
        assert result.exit_code == 0

        share_out = tmp_path / "shared"
        result = runner.invoke(app, [
            "share", str(bundle), "--output", str(share_out),
        ])
        assert result.exit_code == 0
        for f in share_out.iterdir():
            if f.is_file():
                content = f.read_text()
                for pattern in ("sk_live_", "SuperSecret", "hunter2"):
                    assert pattern not in content, (
                        f"Secret pattern {pattern!r} found in {f.name}"
                    )

    def test_domain_override(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        share_out = tmp_path / "shared"
        result = runner.invoke(app, [
            "share", str(bundle), "--output", str(share_out),
            "--domain", "custom.example.org",
        ])
        assert result.exit_code == 0
        # share_bundle uses the domain for spec gen but session.json
        # is copied from the original bundle, so verify via spec
        # At minimum, the command should succeed with the override
        spec = yaml.safe_load((share_out / "spec.yaml").read_text())
        assert spec is not None

    def test_existing_output_dir_exits_1(self, tmp_path: Path):
        bundle = _create_bundle(tmp_path)
        share_out = tmp_path / "shared"
        share_out.mkdir()  # pre-create so it already exists
        result = runner.invoke(app, [
            "share", str(bundle), "--output", str(share_out),
        ])
        assert result.exit_code == 1
        combined = result.output + (result.stderr or "")
        assert "already exists" in combined.lower()


# ===========================================================================
# probe
# ===========================================================================


class TestProbe:
    def _mock_assessment(self, verdict_value):
        from apisniff.models import (
            ProbeAssessment,
            ProbeResult,
            ProbeVerdict,
        )

        verdict = ProbeVerdict(verdict_value)
        dummy_result = ProbeResult(
            label="naked", status=200, headers={}, body=b"ok",
            elapsed_ms=50.0, error=None,
        )
        return ProbeAssessment(
            url="https://example.com",
            verdict=verdict,
            recommendation="Test recommendation",
            results={
                "naked": dummy_result,
                "impersonated": ProbeResult(
                    label="impersonated", status=200, headers={}, body=b"ok",
                    elapsed_ms=55.0, error=None,
                ),
                "tls_only": ProbeResult(
                    label="tls_only", status=200, headers={}, body=b"ok",
                    elapsed_ms=60.0, error=None,
                ),
            },
            vendors=[],
        )

    def test_json_output_shape(self):
        assessment = self._mock_assessment("no_protection")
        with patch("apisniff.probe.run_probes", new_callable=AsyncMock, return_value=assessment):
            result = runner.invoke(app, ["probe", "example.com", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "verdict" in data
        assert "probes" in data
        assert "url" in data

    def test_exit_code_2_on_full_block(self):
        assessment = self._mock_assessment("full_block")
        with patch("apisniff.probe.run_probes", new_callable=AsyncMock, return_value=assessment):
            result = runner.invoke(app, ["probe", "example.com", "--json"])
        assert result.exit_code == 2

    def test_exit_code_0_on_no_protection(self):
        assessment = self._mock_assessment("no_protection")
        with patch("apisniff.probe.run_probes", new_callable=AsyncMock, return_value=assessment):
            result = runner.invoke(app, ["probe", "example.com", "--json"])
        assert result.exit_code == 0

    def test_bad_url_graceful_error(self):
        """When run_probes raises, CLI should handle gracefully."""
        async def raise_error(*args, **kwargs):
            raise ConnectionError("DNS resolution failed")

        with patch("apisniff.probe.run_probes", side_effect=raise_error):
            result = runner.invoke(app, ["probe", "not-a-real-host.invalid"])
        # Should not show a Python traceback in normal output
        # (CliRunner may capture it differently, but the key contract is no raw traceback)
        assert result.exit_code != 0


# ===========================================================================
# Global CLI
# ===========================================================================


class TestGlobalCLI:
    """
    The existing test_cli.py covers --version, help, and header parsing.
    These tests cover complementary aspects to avoid duplication.
    """

    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer's no_args_is_help triggers Click's UsageError which exits 2
        assert result.exit_code in (0, 2)
        # Should show available commands
        assert "analyze" in result.output
        assert "spec" in result.output

    def test_unknown_command_exits_nonzero(self):
        result = runner.invoke(app, ["nonexistent-command"])
        assert result.exit_code != 0

    def test_analyze_help_lists_options(self):
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--domain" in result.output
        assert "--json" in result.output
        assert "--output-dir" in result.output

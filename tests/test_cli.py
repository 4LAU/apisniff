# tests/test_cli.py
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from apisniff import __version__
from apisniff.bundle import MAX_IMPORT_BYTES
from apisniff.cli import _parse_header_args, _parse_probe_target, app

runner = CliRunner()


def test_probe_help():
    result = runner.invoke(app, ["probe", "--help"])
    assert result.exit_code == 0
    assert "defense preflight" in result.output.lower() or "url" in result.output.lower()


def test_main_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "probe" in result.output
    assert "recon" in result.output
    assert "spec" in result.output


def test_main_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output == f"apisniff {__version__}\n"


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


def test_spec_oversized_input_exits_without_traceback(tmp_path: Path):
    input_file = tmp_path / "large.har"
    with input_file.open("wb") as f:
        f.truncate(MAX_IMPORT_BYTES + 1)

    result = runner.invoke(app, ["spec", "example.com", "--input", str(input_file)])

    assert result.exit_code == 1
    assert "Input file is too large" in result.output
    assert "Traceback" not in result.output


def test_spec_omits_examples_by_default(monkeypatch):
    captured = {}

    def fake_run_spec(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("apisniff.spec.run_spec", fake_run_spec)

    result = runner.invoke(app, ["spec", "example.com"])

    assert result.exit_code == 0
    assert captured["include_examples"] is False


def test_spec_examples_are_explicit_opt_in(monkeypatch):
    captured = {}

    def fake_run_spec(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("apisniff.spec.run_spec", fake_run_spec)

    result = runner.invoke(app, ["spec", "example.com", "--examples"])

    assert result.exit_code == 0
    assert captured["include_examples"] is True


def test_spec_include_flags_pass_through(monkeypatch):
    captured = {}

    def fake_run_spec(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("apisniff.spec.run_spec", fake_run_spec)

    result = runner.invoke(app, [
        "spec",
        "example.com",
        "--include-third-party",
        "--include-category",
        "antibot",
        "--include-category",
        "captcha",
        "--include-host",
        "api.example.com",
    ])

    assert result.exit_code == 0
    assert captured["include_third_party"] is True
    assert captured["include_categories"] == ["antibot", "captcha"]
    assert captured["include_hosts"] == ["api.example.com"]

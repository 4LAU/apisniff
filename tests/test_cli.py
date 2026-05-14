# tests/test_cli.py
import pytest
import typer
from typer.testing import CliRunner

from apisniff import __version__
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

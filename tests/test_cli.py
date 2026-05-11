# tests/test_cli.py
from typer.testing import CliRunner

from apisniff.cli import _parse_header_args, app

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


def test_parse_header_rejects_missing_colon():
    import pytest
    import typer
    with pytest.raises(typer.BadParameter, match="missing ':'"):
        _parse_header_args(["badheader"])


def test_parse_header_valid():
    result = _parse_header_args(["Authorization: Bearer tok123", "X-Custom:val"])
    assert result == {"Authorization": "Bearer tok123", "X-Custom": "val"}

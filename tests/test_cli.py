# tests/test_cli.py
from typer.testing import CliRunner

from apisniff.cli import app

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

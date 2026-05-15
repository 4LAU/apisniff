from __future__ import annotations

import importlib
import stat
import sys

import pytest


def _drop_proxy_module() -> None:
    module = sys.modules.pop("apisniff.proxy", None)
    if module is not None:
        for addon in getattr(module, "addons", []):
            addon.done()


def _import_proxy(monkeypatch: pytest.MonkeyPatch, *, target: str | None, output: str | None):
    _drop_proxy_module()
    if target is None:
        monkeypatch.delenv("APISNIFF_TARGET", raising=False)
    else:
        monkeypatch.setenv("APISNIFF_TARGET", target)

    if output is None:
        monkeypatch.delenv("APISNIFF_OUTPUT", raising=False)
    else:
        monkeypatch.setenv("APISNIFF_OUTPUT", output)

    return importlib.import_module("apisniff.proxy")


def test_proxy_import_requires_target_env(monkeypatch):
    with pytest.raises(KeyError, match="APISNIFF_TARGET"):
        _import_proxy(monkeypatch, target=None, output="/tmp/apisniff-test.jsonl")


def test_proxy_import_requires_output_env(monkeypatch):
    with pytest.raises(KeyError, match="APISNIFF_OUTPUT"):
        _import_proxy(monkeypatch, target="example.com", output=None)


def test_new_capture_output_file_has_restricted_permissions(monkeypatch, tmp_path):
    output_path = tmp_path / "capture.jsonl"
    _import_proxy(monkeypatch, target="example.com", output=str(output_path))

    try:
        mode = stat.S_IMODE(output_path.stat().st_mode)
        assert mode == 0o600
    finally:
        _drop_proxy_module()

from __future__ import annotations

import importlib
import stat
import sys

import pytest

from apisniff.models import CapturedFlow


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


def test_proxy_preserves_non_options_noise_before_projection(monkeypatch, tmp_path):
    output_path = tmp_path / "capture.jsonl"
    proxy = _import_proxy(monkeypatch, target="example.com", output=str(output_path))
    addon = proxy.ApisniffAddon("example.com", str(output_path))
    flow = CapturedFlow(
        method="GET",
        host="example.com",
        path="/style.css",
        url="https://example.com/style.css",
        request_headers={},
        request_body=b"",
        response_status=200,
        response_headers={"content-type": "text/css"},
        response_body=b"body{}",
    )
    monkeypatch.setattr(proxy, "flow_to_captured", lambda _: flow)

    try:
        addon.response(object())
        addon.done()

        lines = output_path.read_text().strip().splitlines()
        assert len(lines) == 1
        assert "surface:static" in lines[0]
        assert (tmp_path / "surface.jsonl").exists()
        assert (tmp_path / "surface-context.json").exists()
    finally:
        addon.done()
        _drop_proxy_module()

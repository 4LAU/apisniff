"""Tests for the mitmproxy adapter.

mitmproxy is a heavy runtime dependency not installed in the test environment,
so these tests use lightweight stand-ins for its Headers and flow objects.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from apisniff.adapters.mitmproxy_adapter import _build_headers, flow_to_captured


class MockHeaders:
    def __init__(self, pairs: list[tuple[str, str]]):
        self._pairs = pairs

    def items(self):
        return list(self._pairs)

    def get_all(self, key: str) -> list[str]:
        return [v for k, v in self._pairs if k.lower() == key.lower()]


def test_build_headers_preserves_multi_value_semantics():
    headers = MockHeaders([
        ("Set-Cookie", "session=abc; Path=/"),
        ("Set-Cookie", "csrf=xyz; Path=/"),
        ("WWW-Authenticate", 'Bearer realm="api"'),
        ("WWW-Authenticate", 'Basic realm="legacy"'),
    ])

    result = _build_headers(headers)

    assert result["set-cookie"] == "session=abc; Path=/\ncsrf=xyz; Path=/"
    assert result["www-authenticate"] == 'Bearer realm="api", Basic realm="legacy"'


def _make_flow(
    *,
    req_headers: list[tuple[str, str]] | None = None,
    res_headers: list[tuple[str, str]] | None = None,
    has_response: bool = True,
) -> MagicMock:
    flow = MagicMock()
    req = flow.request
    req.method = "GET"
    req.host = "example.com"
    req.path = "/api/resource"
    req.pretty_url = "https://example.com/api/resource"
    req.headers = MockHeaders(req_headers or [("accept", "application/json")])
    req.get_content.return_value = b""

    if has_response:
        res = flow.response
        res.status_code = 200
        res.headers = MockHeaders(res_headers or [("content-type", "application/json")])
        res.get_content.return_value = b'{"ok": true}'
    else:
        flow.response = None

    return flow


def test_flow_to_captured_preserves_core_mitmproxy_fields():
    captured = flow_to_captured(_make_flow(req_headers=[
        ("accept", "application/json"),
        ("accept", "text/html"),
    ]))

    assert captured.method == "GET"
    assert captured.host == "example.com"
    assert captured.path == "/api/resource"
    assert captured.url == "https://example.com/api/resource"
    assert captured.request_headers["accept"] == "application/json, text/html"
    assert captured.response_status == 200
    assert captured.response_body == b'{"ok": true}'


def test_flow_to_captured_without_response_uses_empty_response_fields():
    captured = flow_to_captured(_make_flow(has_response=False))

    assert captured.response_status == 0
    assert captured.response_headers == {}
    assert captured.response_body == b""

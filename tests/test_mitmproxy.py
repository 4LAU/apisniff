"""Tests for the mitmproxy adapter.

mitmproxy is a heavy runtime dependency not installed in the test environment,
so we use lightweight mocks for its Headers and flow objects.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from apisniff.adapters.mitmproxy_adapter import _build_headers, flow_to_captured


class MockHeaders:
    """Minimal mock of mitmproxy.net.http.Headers."""

    def __init__(self, pairs: list[tuple[str, str]]):
        self._pairs = pairs

    def items(self):
        return list(self._pairs)

    def get_all(self, key: str) -> list[str]:
        return [v for k, v in self._pairs if k.lower() == key.lower()]


# ---------------------------------------------------------------------------
# _build_headers unit tests
# ---------------------------------------------------------------------------


def test_single_value_header():
    h = MockHeaders([("Content-Type", "application/json")])
    assert _build_headers(h) == {"content-type": "application/json"}


def test_keys_are_lowercased():
    h = MockHeaders([("X-Request-ID", "abc123")])
    result = _build_headers(h)
    assert "x-request-id" in result
    assert result["x-request-id"] == "abc123"


def test_set_cookie_joined_with_newline():
    h = MockHeaders([
        ("set-cookie", "session=abc; Path=/"),
        ("set-cookie", "csrf=xyz; Path=/"),
    ])
    result = _build_headers(h)
    assert result["set-cookie"] == "session=abc; Path=/\ncsrf=xyz; Path=/"


def test_www_authenticate_multi_value_joined_with_comma():
    """Multi-value www-authenticate headers must be joined with ', '."""
    h = MockHeaders([
        ("www-authenticate", "Bearer realm=\"api\""),
        ("www-authenticate", "Basic realm=\"legacy\""),
    ])
    result = _build_headers(h)
    assert result["www-authenticate"] == 'Bearer realm="api", Basic realm="legacy"'


def test_link_multi_value_joined_with_comma():
    h = MockHeaders([
        ("link", "<https://example.com/page/1>; rel=\"next\""),
        ("link", "<https://example.com/page/3>; rel=\"prev\""),
    ])
    result = _build_headers(h)
    assert result["link"] == (
        '<https://example.com/page/1>; rel="next", '
        '<https://example.com/page/3>; rel="prev"'
    )


def test_single_set_cookie_not_newline_joined():
    """A single set-cookie value must NOT get a trailing newline."""
    h = MockHeaders([("set-cookie", "session=abc; Path=/")])
    result = _build_headers(h)
    assert result["set-cookie"] == "session=abc; Path=/"


def test_duplicate_keys_deduplicated():
    """Only one key per header name in the output dict."""
    h = MockHeaders([
        ("vary", "Accept"),
        ("vary", "Accept-Encoding"),
    ])
    result = _build_headers(h)
    assert list(result.keys()).count("vary") == 1
    assert result["vary"] == "Accept, Accept-Encoding"


# ---------------------------------------------------------------------------
# flow_to_captured integration tests
# ---------------------------------------------------------------------------


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


def test_flow_to_captured_basic():
    flow = _make_flow()
    captured = flow_to_captured(flow)
    assert captured.method == "GET"
    assert captured.host == "example.com"
    assert captured.response_status == 200


def test_flow_to_captured_request_multi_value_header():
    """Multi-value request headers are joined with ', '."""
    flow = _make_flow(req_headers=[
        ("accept", "application/json"),
        ("accept", "text/html"),
    ])
    captured = flow_to_captured(flow)
    assert captured.request_headers["accept"] == "application/json, text/html"


def test_flow_to_captured_response_www_authenticate():
    """Multi-value www-authenticate response headers are joined with ', '."""
    flow = _make_flow(res_headers=[
        ("www-authenticate", "Bearer realm=\"api\""),
        ("www-authenticate", "Basic realm=\"legacy\""),
    ])
    captured = flow_to_captured(flow)
    assert captured.response_headers["www-authenticate"] == (
        'Bearer realm="api", Basic realm="legacy"'
    )


def test_flow_to_captured_no_response():
    flow = _make_flow(has_response=False)
    captured = flow_to_captured(flow)
    assert captured.response_status == 0
    assert captured.response_headers == {}
    assert captured.response_body == b""

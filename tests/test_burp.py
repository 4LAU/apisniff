"""
Tier 2 wire-contract tests for burp_to_flows.

Each test guards a specific silent-corruption mode: a bug that would produce
wrong data with no crash and no visible signal in production.

Without these tests, a change could ship that:
- fails to decode base64-encoded request/response and nobody would know
- extracts the wrong host/path from the URL and nobody would know
- drops query strings from path and nobody would know
- silently swaps request and response headers and nobody would know
- fails to join multi-value set-cookie headers correctly and nobody would know
"""

from __future__ import annotations

from apisniff.adapters.burp import burp_to_flows

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Precomputed base64 of raw HTTP messages used across tests.
# GET /api/users?page=1 with Authorization + Content-Type headers, no body.
_REQ_B64 = (
    "R0VUIC9hcGkvdXNlcnM/cGFnZT0xIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0K"
    "QXV0aG9yaXphdGlvbjogQmVhcmVyIHRva2VuMTIzDQpDb250ZW50LVR5cGU6IGFwcGxp"
    "Y2F0aW9uL2pzb24NCg0K"
)
# HTTP/1.1 200 OK with Content-Type + X-Request-Id headers, body {"users": []}
_RESP_B64 = (
    "SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NClgt"
    "UmVxdWVzdC1JZDogYWJjMTIzDQoNCnsidXNlcnMiOiBbXX0="
)
# POST /api/items with body
_POST_REQ_B64 = (
    "UE9TVCAvYXBpL2l0ZW1zIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KQ29udGVu"
    "dC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uDQoNCnsibmFtZSI6ICJ3aWRnZXQifQ=="
)
# 201 Created with two Set-Cookie headers, body {"id": 1}
_POST_RESP_B64 = (
    "SFRUUC8xLjEgMjAxIENyZWF0ZWQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNv"
    "bg0KU2V0LUNvb2tpZTogc2Vzc2lvbj1hYmMNClNldC1Db29raWU6IGNzcmY9eHl6DQoN"
    "CnsiaWQiOiAxfQ=="
)


def _xml(items: list[str]) -> str:
    return '<?xml version="1.0"?>\n<items>\n' + "\n".join(items) + "\n</items>"


def _item(
    *,
    method: str = "GET",
    url: str = "https://example.com/api/users?page=1",
    status: int = 200,
    request_b64: str | None = None,
    response_b64: str | None = None,
    request_plain: str | None = None,
    response_plain: str | None = None,
) -> str:
    # XML requires & to be escaped as &amp; in element text
    xml_url = url.replace("&", "&amp;")

    if request_b64 is not None:
        req_tag = f'<request base64="true">{request_b64}</request>'
    elif request_plain is not None:
        req_tag = f"<request>{_xml_escape(request_plain)}</request>"
    else:
        req_tag = "<request />"

    if response_b64 is not None:
        resp_tag = f'<response base64="true">{response_b64}</response>'
    elif response_plain is not None:
        resp_tag = f"<response>{_xml_escape(response_plain)}</response>"
    else:
        resp_tag = "<response />"

    return (
        f"  <item>\n"
        f"    <method>{method}</method>\n"
        f"    <url>{xml_url}</url>\n"
        f"    <status>{status}</status>\n"
        f"    {req_tag}\n"
        f"    {resp_tag}\n"
        f"  </item>"
    )


# ---------------------------------------------------------------------------
# Empty XML → empty list
# ---------------------------------------------------------------------------

def test_empty_xml_returns_empty_list():
    """Without this test, a change could return a non-empty list for empty XML
    and nobody would know."""
    result = burp_to_flows(_xml([]))
    assert result == []


# ---------------------------------------------------------------------------
# Basic flow extraction — method, status, host, URL verbatim
# ---------------------------------------------------------------------------

def test_method_and_status_extracted():
    """Without this test, method/status could be hardcoded defaults and nobody
    would know until filtering by method or status silently excluded flows."""
    flows = burp_to_flows(_xml([_item(method="DELETE", status=204,
                                      url="https://example.com/api/items/1")]))
    assert flows[0].method == "DELETE"
    assert flows[0].response_status == 204


def test_url_stored_verbatim():
    """Without this test, the stored URL could be stripped of query params and
    nobody would know until replay produced wrong requests."""
    url = "https://example.com/api/users?page=1"
    flows = burp_to_flows(_xml([_item(url=url)]))
    assert flows[0].url == url


def test_host_extracted_from_url():
    """Without this test, host could be the full URL or empty and nobody would
    know until vendor detection produced wrong results."""
    flows = burp_to_flows(_xml([_item(url="https://api.example.com/v1/items")]))
    assert flows[0].host == "api.example.com"


# ---------------------------------------------------------------------------
# Path includes query string
# ---------------------------------------------------------------------------

def test_path_includes_query_string():
    """Without this test, the query string could be stripped from path and
    nobody would know until endpoint deduplication collapsed distinct endpoints."""
    flows = burp_to_flows(_xml([_item(url="https://example.com/api/users?page=1&limit=20")]))
    assert flows[0].path == "/api/users?page=1&limit=20"


def test_path_without_query_string():
    """Without this test, a path with no query string could gain a trailing '?'
    and nobody would know."""
    flows = burp_to_flows(_xml([_item(url="https://example.com/api/users")]))
    assert flows[0].path == "/api/users"


# ---------------------------------------------------------------------------
# Base64-encoded request/response decoding
# ---------------------------------------------------------------------------

def test_base64_request_decoded():
    """Without this test, base64 decoding could be skipped and nobody would know
    until header extraction produced garbage."""
    flows = burp_to_flows(_xml([_item(request_b64=_REQ_B64, response_b64=_RESP_B64)]))
    flow = flows[0]
    assert "authorization" in flow.request_headers
    assert flow.request_headers["authorization"] == "Bearer token123"


def test_base64_response_body_decoded():
    """Without this test, the response body could be the raw base64 string and
    nobody would know until schema inference failed on non-JSON content."""
    flows = burp_to_flows(_xml([_item(request_b64=_REQ_B64, response_b64=_RESP_B64)]))
    assert flows[0].response_body == b'{"users": []}'


# ---------------------------------------------------------------------------
# Header extraction from raw HTTP
# ---------------------------------------------------------------------------

def test_request_headers_extracted_and_lowercased():
    """Without this test, header keys could be mixed-case or completely missing
    and nobody would know until auth-header detection silently failed."""
    flows = burp_to_flows(_xml([_item(request_b64=_REQ_B64, response_b64=_RESP_B64)]))
    req_h = flows[0].request_headers
    assert "authorization" in req_h
    assert "content-type" in req_h
    assert req_h["content-type"] == "application/json"
    # Mixed-case key must not also appear
    assert "Authorization" not in req_h


def test_response_headers_extracted():
    """Without this test, response headers could be empty or swapped with request
    headers and nobody would know until Content-Type-based routing broke."""
    flows = burp_to_flows(_xml([_item(request_b64=_REQ_B64, response_b64=_RESP_B64)]))
    resp_h = flows[0].response_headers
    assert "content-type" in resp_h
    assert resp_h["content-type"] == "application/json"
    assert "x-request-id" in resp_h
    assert resp_h["x-request-id"] == "abc123"


def test_request_headers_not_swapped_with_response_headers():
    """Without this test, a swap bug would silently put auth tokens in response
    headers and nobody would know."""
    flows = burp_to_flows(_xml([_item(request_b64=_REQ_B64, response_b64=_RESP_B64)]))
    flow = flows[0]
    assert "authorization" in flow.request_headers
    assert "authorization" not in flow.response_headers
    assert "x-request-id" in flow.response_headers
    assert "x-request-id" not in flow.request_headers


def test_request_line_not_parsed_as_header():
    """Without this test, 'GET /api/users?page=1 HTTP/1.1' could appear as a
    malformed header key and nobody would know."""
    flows = burp_to_flows(_xml([_item(request_b64=_REQ_B64, response_b64=_RESP_B64)]))
    req_h = flows[0].request_headers
    # None of the keys should look like a request line fragment
    for key in req_h:
        assert "HTTP" not in key
        assert "GET" not in key


# ---------------------------------------------------------------------------
# POST body preserved
# ---------------------------------------------------------------------------

def test_post_body_preserved():
    """Without this test, a request body could be silently dropped and nobody
    would know until diff-classification had nothing to compare."""
    flows = burp_to_flows(_xml([
        _item(method="POST", url="https://example.com/api/items", status=201,
              request_b64=_POST_REQ_B64, response_b64=_POST_RESP_B64)
    ]))
    assert flows[0].request_body == b'{"name": "widget"}'


# ---------------------------------------------------------------------------
# Multi-value Set-Cookie joined with newline
# ---------------------------------------------------------------------------

def test_set_cookie_joined_with_newline():
    """Without this test, multiple Set-Cookie headers could be joined with ', '
    which breaks cookie parsing downstream and nobody would know."""
    flows = burp_to_flows(_xml([
        _item(method="POST", url="https://example.com/api/items", status=201,
              request_b64=_POST_REQ_B64, response_b64=_POST_RESP_B64)
    ]))
    resp_h = flows[0].response_headers
    assert "set-cookie" in resp_h
    cookies = resp_h["set-cookie"].split("\n")
    assert len(cookies) == 2
    assert "session=abc" in cookies
    assert "csrf=xyz" in cookies


# ---------------------------------------------------------------------------
# Plain-text (non-base64) request/response
# ---------------------------------------------------------------------------

def test_plain_text_request_parsed():
    """Without this test, plain-text (non-base64) raw HTTP would be treated as
    base64 and produce garbage and nobody would know."""
    plain_req = "GET /health HTTP/1.1\r\nHost: example.com\r\nX-Custom: hello\r\n\r\n"
    plain_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    flows = burp_to_flows(_xml([
        _item(url="https://example.com/health", status=200,
              request_plain=plain_req, response_plain=plain_resp)
    ]))
    flow = flows[0]
    assert flow.request_headers.get("x-custom") == "hello"
    assert flow.response_body == b"ok"
    assert flow.response_headers.get("content-type") == "text/plain"


# ---------------------------------------------------------------------------
# Multiple items produce multiple flows in order
# ---------------------------------------------------------------------------

def test_multiple_items_all_converted():
    """Without this test, a change could return only the first item and nobody
    would know."""
    items = [
        _item(url="https://example.com/a", status=200),
        _item(url="https://example.com/b", status=404),
    ]
    flows = burp_to_flows(_xml(items))
    assert len(flows) == 2
    assert flows[0].path == "/a"
    assert flows[1].path == "/b"
    assert flows[0].response_status == 200
    assert flows[1].response_status == 404

"""
Tier 2 wire-contract tests for har_to_flows.

Each test guards a specific silent-corruption mode: a bug that would produce
wrong data with no crash and no visible signal in production.

Without these tests, a change could ship that:
- maps request headers into response_headers and nobody would know
- extracts the wrong host/path from the URL and nobody would know
- silently drops the response body and nobody would know
- silently drops a POST body and nobody would know
- produces one CapturedFlow when two entries exist and nobody would know
"""

from __future__ import annotations

import json

import pytest

from apisniff.adapters.har import har_to_flows


def _har(entries: list[dict]) -> str:
    return json.dumps({"log": {"entries": entries}})


def _entry(
    *,
    method: str = "GET",
    url: str = "https://api.example.com/v1/items",
    req_headers: list[dict] | None = None,
    post_data_text: str | None = None,
    status: int = 200,
    resp_headers: list[dict] | None = None,
    resp_body: str = "",
) -> dict:
    req: dict = {
        "method": method,
        "url": url,
        "headers": req_headers or [],
    }
    if post_data_text is not None:
        req["postData"] = {"text": post_data_text}

    resp: dict = {
        "status": status,
        "headers": resp_headers or [],
        "content": {"text": resp_body},
    }
    return {"request": req, "response": resp}


# ---------------------------------------------------------------------------
# Empty HAR → empty list (not crash; listed for completeness — crash is visible,
# but an incorrectly non-empty result would be silent)
# ---------------------------------------------------------------------------

def test_empty_har_returns_empty_list():
    """Without this test, a change could ship that returns a non-empty list
    for an empty HAR and nobody would know."""
    result = har_to_flows(_har([]))
    assert result == []


# ---------------------------------------------------------------------------
# Host and path extracted from URL, not from some wrong field
# ---------------------------------------------------------------------------

def test_host_extracted_from_url():
    """Without this test, a change could ship that sets host to the full URL
    or an empty string and nobody would know."""
    flows = har_to_flows(_har([_entry(url="https://api.example.com/v1/items?q=1")]))
    assert flows[0].host == "api.example.com"


def test_path_extracted_from_url():
    """Without this test, a change could ship that sets path to '' or the full
    URL and nobody would know."""
    flows = har_to_flows(_har([_entry(url="https://api.example.com/v1/items?q=1")]))
    assert flows[0].path == "/v1/items"


# ---------------------------------------------------------------------------
# Request headers mapped to request_headers, not response_headers
# ---------------------------------------------------------------------------

def test_request_headers_not_swapped_with_response_headers():
    """Without this test, a change could swap req/resp header dicts and nobody
    would know until vendor detection produced wrong results."""
    req_h = [{"name": "Authorization", "value": "Bearer token123"}]
    resp_h = [{"name": "Content-Type", "value": "application/json"}]
    flows = har_to_flows(_har([_entry(req_headers=req_h, resp_headers=resp_h)]))
    flow = flows[0]
    assert "authorization" in flow.request_headers
    assert flow.request_headers["authorization"] == "Bearer token123"
    assert "authorization" not in flow.response_headers
    assert "content-type" in flow.response_headers
    assert flow.response_headers["content-type"] == "application/json"


def test_header_names_lowercased():
    """Without this test, mixed-case header names would silently cause lookup
    misses in vendor detection."""
    req_h = [{"name": "X-Api-Key", "value": "abc"}]
    flows = har_to_flows(_har([_entry(req_headers=req_h)]))
    assert "x-api-key" in flows[0].request_headers
    assert "X-Api-Key" not in flows[0].request_headers


# ---------------------------------------------------------------------------
# Response body not silently lost
# ---------------------------------------------------------------------------

def test_response_body_preserved():
    """Without this test, a change could zero out response_body and nobody
    would know until schema inference produced empty specs."""
    body_text = '{"id": 42, "name": "widget"}'
    flows = har_to_flows(_har([_entry(resp_body=body_text)]))
    assert flows[0].response_body == body_text.encode("utf-8")


# ---------------------------------------------------------------------------
# POST body not silently lost
# ---------------------------------------------------------------------------

def test_post_body_preserved():
    """Without this test, a change could drop request_body for POST entries
    and nobody would know until diff-classification had no body to compare."""
    payload = '{"username": "alice", "password": "s3cr3t"}'
    flows = har_to_flows(_har([_entry(method="POST", post_data_text=payload)]))
    assert flows[0].request_body == payload.encode("utf-8")


def test_get_request_body_is_empty_bytes():
    """Without this test, a missing postData could produce None instead of b''
    and silently crash downstream consumers that call len()."""
    flows = har_to_flows(_har([_entry(method="GET")]))
    assert flows[0].request_body == b""


# ---------------------------------------------------------------------------
# Multiple entries produce multiple CapturedFlows in order
# ---------------------------------------------------------------------------

def test_multiple_entries_all_converted():
    """Without this test, a change could return only the first entry and nobody
    would know."""
    entries = [
        _entry(url="https://api.example.com/a", status=200),
        _entry(url="https://api.example.com/b", status=404),
    ]
    flows = har_to_flows(_har(entries))
    assert len(flows) == 2
    assert flows[0].path == "/a"
    assert flows[1].path == "/b"
    assert flows[0].response_status == 200
    assert flows[1].response_status == 404


# ---------------------------------------------------------------------------
# Method and status faithfully copied
# ---------------------------------------------------------------------------

def test_method_and_status_copied():
    """Without this test, method/status could be hardcoded defaults and nobody
    would know until filtering by method or status silently excluded flows."""
    flows = har_to_flows(_har([_entry(method="DELETE", status=204)]))
    assert flows[0].method == "DELETE"
    assert flows[0].response_status == 204


# ---------------------------------------------------------------------------
# URL stored verbatim (query string intact)
# ---------------------------------------------------------------------------

def test_url_stored_verbatim():
    """Without this test, the stored URL could be stripped of query params and
    nobody would know until replay/export produced wrong requests."""
    url = "https://api.example.com/search?q=foo&page=2"
    flows = har_to_flows(_har([_entry(url=url)]))
    assert flows[0].url == url

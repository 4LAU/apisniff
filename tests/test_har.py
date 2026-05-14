from __future__ import annotations

import base64
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
    resp_encoding: str | None = None,
    started_date_time: str | None = None,
) -> dict:
    request: dict = {"method": method, "url": url, "headers": req_headers or []}
    if post_data_text is not None:
        request["postData"] = {"text": post_data_text}

    content: dict = {"text": resp_body}
    if resp_encoding is not None:
        content["encoding"] = resp_encoding

    entry: dict = {
        "request": request,
        "response": {
            "status": status,
            "headers": resp_headers or [],
            "content": content,
        },
    }
    if started_date_time is not None:
        entry["startedDateTime"] = started_date_time
    return entry


def test_har_entries_convert_without_silent_field_corruption():
    """HAR conversion preserves request/response boundaries and endpoint identity."""
    req_headers = [{"name": "Authorization", "value": "Bearer token123"}]
    resp_headers = [{"name": "Content-Type", "value": "application/json"}]
    flows = har_to_flows(_har([
        _entry(
            method="POST",
            url="https://api.example.com/v1/items?q=1",
            req_headers=req_headers,
            post_data_text='{"name":"widget"}',
            status=201,
            resp_headers=resp_headers,
            resp_body='{"id":42}',
            started_date_time="2024-03-15T10:30:00Z",
        ),
        _entry(url="https://api.example.com/v1/other", status=404),
    ]))

    assert [(f.method, f.response_status, f.path) for f in flows] == [
        ("POST", 201, "/v1/items?q=1"),
        ("GET", 404, "/v1/other"),
    ]
    first = flows[0]
    assert first.host == "api.example.com"
    assert first.url == "https://api.example.com/v1/items?q=1"
    assert first.request_headers["authorization"] == "Bearer token123"
    assert "authorization" not in first.response_headers
    assert first.response_headers["content-type"] == "application/json"
    assert first.request_body == b'{"name":"widget"}'
    assert first.response_body == b'{"id":42}'
    assert first.timestamp == pytest.approx(1710498600.0, abs=1.0)


def test_har_base64_response_body_decoded():
    raw = b"\x89PNG\r\n\x1a\n"
    encoded = base64.b64encode(raw).decode("ascii")
    flows = har_to_flows(_har([_entry(resp_body=encoded, resp_encoding="base64")]))
    assert flows[0].response_body == raw


def test_har_duplicate_set_cookie_headers_joined_with_newline():
    resp_headers = [
        {"name": "Set-Cookie", "value": "session=abc; HttpOnly"},
        {"name": "Set-Cookie", "value": "theme=dark; SameSite=Lax"},
    ]
    flows = har_to_flows(_har([_entry(resp_headers=resp_headers)]))
    assert flows[0].response_headers["set-cookie"] == (
        "session=abc; HttpOnly\ntheme=dark; SameSite=Lax"
    )

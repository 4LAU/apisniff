from __future__ import annotations

import pytest
from defusedxml.common import DefusedXmlException

from apisniff.adapters.burp import burp_to_flows


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_REQ_B64 = (
    "UE9TVCAvYXBpL2l0ZW1zP3BhZ2U9MSBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20N"
    "CkF1dGhvcml6YXRpb246IEJlYXJlciB0b2tlbjEyMw0KQ29udGVudC1UeXBlOiBhcHBs"
    "aWNhdGlvbi9qc29uDQoNCnsibmFtZSI6ICJ3aWRnZXQifQ=="
)
_RESP_B64 = (
    "SFRUUC8xLjEgMjAxIENyZWF0ZWQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNv"
    "bg0KWC1SZXF1ZXN0LUlkOiBhYmMxMjMNCg0KeyJpZCI6IDF9"
)
_COOKIE_RESP_B64 = (
    "SFRUUC8xLjEgMjAxIENyZWF0ZWQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNv"
    "bg0KU2V0LUNvb2tpZTogc2Vzc2lvbj1hYmMNClNldC1Db29raWU6IGNzcmY9eHl6DQoN"
    "CnsiaWQiOiAxfQ=="
)


def _xml(items: list[str]) -> str:
    return '<?xml version="1.0"?>\n<items>\n' + "\n".join(items) + "\n</items>"


def _item(
    *,
    method: str = "POST",
    url: str = "https://example.com/api/items?page=1",
    status: int = 201,
    request_b64: str | None = _REQ_B64,
    response_b64: str | None = _RESP_B64,
    request_plain: str | None = None,
    response_plain: str | None = None,
) -> str:
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
        "  <item>\n"
        f"    <method>{method}</method>\n"
        f"    <url>{xml_url}</url>\n"
        f"    <status>{status}</status>\n"
        f"    {req_tag}\n"
        f"    {resp_tag}\n"
        "  </item>"
    )


def test_burp_base64_http_messages_convert_without_silent_field_corruption():
    flows = burp_to_flows(_xml([
        _item(),
        _item(url="https://example.com/api/other", status=404, request_b64=None, response_b64=None),
    ]))

    assert [(f.method, f.response_status, f.path) for f in flows] == [
        ("POST", 201, "/api/items?page=1"),
        ("POST", 404, "/api/other"),
    ]
    first = flows[0]
    assert first.host == "example.com"
    assert first.url == "https://example.com/api/items?page=1"
    assert first.request_headers["authorization"] == "Bearer token123"
    assert "authorization" not in first.response_headers
    assert first.response_headers["x-request-id"] == "abc123"
    assert first.request_body == b'{"name": "widget"}'
    assert first.response_body == b'{"id": 1}'


def test_burp_duplicate_set_cookie_headers_joined_with_newline():
    flows = burp_to_flows(_xml([_item(response_b64=_COOKIE_RESP_B64)]))
    assert flows[0].response_headers["set-cookie"] == "session=abc\ncsrf=xyz"


def test_burp_plain_text_http_messages_are_parsed():
    plain_req = "GET /health HTTP/1.1\r\nHost: example.com\r\nX-Custom: hello\r\n\r\n"
    plain_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    flow = burp_to_flows(_xml([
        _item(
            method="GET",
            url="https://example.com/health",
            status=200,
            request_b64=None,
            response_b64=None,
            request_plain=plain_req,
            response_plain=plain_resp,
        )
    ]))[0]

    assert flow.request_headers["x-custom"] == "hello"
    assert flow.response_headers["content-type"] == "text/plain"
    assert flow.response_body == b"ok"


def test_burp_doctype_declaration_is_rejected_by_defusedxml():
    xml = """<?xml version="1.0"?>
<!DOCTYPE items [
  <!ENTITY expanded "blocked">
]>
<items>
  <item>
    <method>GET</method>
    <url>https://example.com/</url>
    <status>200</status>
    <request />
    <response />
  </item>
</items>"""

    with pytest.raises(DefusedXmlException):
        burp_to_flows(xml)

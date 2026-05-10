from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from apisniff.models import CapturedFlow


def _decode_raw(element: ET.Element) -> bytes:
    """Return raw bytes from a <request> or <response> element.

    When base64="true" is set, the text is base64-encoded; otherwise plain.
    """
    text = element.text or ""
    if element.get("base64") == "true":
        return base64.b64decode(text)
    return text.encode("utf-8")


def _parse_raw_headers(header_block: str) -> dict[str, str]:
    """Parse the header section of a raw HTTP message (excludes the first line).

    Multi-value headers are joined with ", " except set-cookie which uses "\\n".
    """
    grouped: dict[str, list[str]] = {}
    for line in header_block.split("\r\n"):
        if not line:
            continue
        colon = line.find(":")
        if colon == -1:
            continue
        key = line[:colon].strip().lower()
        value = line[colon + 1:].strip()
        grouped.setdefault(key, []).append(value)

    result: dict[str, str] = {}
    for key, values in grouped.items():
        if key == "set-cookie":
            result[key] = "\n".join(values)
        else:
            result[key] = ", ".join(values)
    return result


def _split_http_message(raw: bytes) -> tuple[dict[str, str], bytes]:
    """Split a raw HTTP message into (headers_dict, body_bytes).

    The first line (request line or status line) is discarded.
    """
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx == -1:
        header_bytes = raw
        body = b""
    else:
        header_bytes = raw[:idx]
        body = raw[idx + len(sep):]

    lines = header_bytes.decode("utf-8", errors="replace").split("\r\n")
    # Drop the first line (GET /path HTTP/1.1 or HTTP/1.1 200 OK)
    header_lines = "\r\n".join(lines[1:])
    return _parse_raw_headers(header_lines), body


def burp_to_flows(xml_text: str) -> list[CapturedFlow]:
    """Parse a Burp Suite XML export and return a list of CapturedFlow objects."""
    root = ET.fromstring(xml_text)
    flows: list[CapturedFlow] = []

    for item in root.iter("item"):
        method_el = item.find("method")
        url_el = item.find("url")
        status_el = item.find("status")
        request_el = item.find("request")
        response_el = item.find("response")

        url = url_el.text.strip() if url_el is not None and url_el.text else ""
        parsed = urlparse(url)

        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query

        method = method_el.text.strip() if method_el is not None and method_el.text else "GET"
        status = int(status_el.text.strip()) if status_el is not None and status_el.text else 0

        if request_el is not None:
            raw_req = _decode_raw(request_el)
            req_headers, req_body = _split_http_message(raw_req)
        else:
            req_headers, req_body = {}, b""

        if response_el is not None:
            raw_resp = _decode_raw(response_el)
            resp_headers, resp_body = _split_http_message(raw_resp)
        else:
            resp_headers, resp_body = {}, b""

        flows.append(CapturedFlow(
            method=method,
            host=parsed.hostname or "",
            path=path,
            url=url,
            request_headers=req_headers,
            request_body=req_body,
            response_status=status,
            response_headers=resp_headers,
            response_body=resp_body,
        ))

    return flows

from __future__ import annotations

import base64
import json
from datetime import datetime
from urllib.parse import urlparse

from apisniff.models import CapturedFlow


def _parse_headers(header_list: list[dict]) -> dict[str, str]:
    """Group HAR headers by lowercased name.

    Per RFC 9110 multiple values for the same header are joined with ", ",
    except Set-Cookie which must remain newline-separated so each directive
    is individually parseable.
    """
    grouped: dict[str, list[str]] = {}
    for h in header_list:
        key = h["name"].lower()
        grouped.setdefault(key, []).append(h["value"])

    result: dict[str, str] = {}
    for key, values in grouped.items():
        if key == "set-cookie":
            result[key] = "\n".join(values)
        else:
            result[key] = ", ".join(values)
    return result


def _parse_timestamp(entry: dict) -> float:
    raw = entry.get("startedDateTime")
    if not raw:
        return 0.0
    try:
        normalized = raw.rstrip("Z")
        if raw.endswith("Z"):
            normalized += "+00:00"
        return datetime.fromisoformat(normalized).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def har_to_flows(har_text: str) -> list[CapturedFlow]:
    data = json.loads(har_text)
    entries = data.get("log", {}).get("entries", [])
    flows: list[CapturedFlow] = []

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})

        url = req.get("url", "")
        parsed = urlparse(url)

        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query

        req_headers = _parse_headers(req.get("headers", []))
        resp_headers = _parse_headers(resp.get("headers", []))

        req_body = (req.get("postData", {}) or {}).get("text", "") or ""

        content = resp.get("content", {}) or {}
        resp_body_text = content.get("text", "") or ""
        if content.get("encoding") == "base64" and resp_body_text:
            resp_body: bytes = base64.b64decode(resp_body_text)
        else:
            resp_body = (
                resp_body_text.encode("utf-8")
                if isinstance(resp_body_text, str) else resp_body_text
            )

        flows.append(CapturedFlow(
            method=req.get("method", "GET"),
            host=parsed.hostname or "",
            path=path,
            url=url,
            request_headers=req_headers,
            request_body=req_body.encode("utf-8") if isinstance(req_body, str) else req_body,
            response_status=resp.get("status", 0),
            response_headers=resp_headers,
            response_body=resp_body,
            timestamp=_parse_timestamp(entry),
        ))

    return flows

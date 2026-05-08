from __future__ import annotations

import json
from urllib.parse import urlparse

from apisniff.models import CapturedFlow


def har_to_flows(har_text: str) -> list[CapturedFlow]:
    data = json.loads(har_text)
    entries = data.get("log", {}).get("entries", [])
    flows: list[CapturedFlow] = []

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})

        url = req.get("url", "")
        parsed = urlparse(url)

        req_headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        resp_headers = {h["name"].lower(): h["value"] for h in resp.get("headers", [])}

        req_body = (req.get("postData", {}) or {}).get("text", "") or ""
        resp_body = (resp.get("content", {}) or {}).get("text", "") or ""

        flows.append(CapturedFlow(
            method=req.get("method", "GET"),
            host=parsed.hostname or "",
            path=parsed.path or "/",
            url=url,
            request_headers=req_headers,
            request_body=req_body.encode("utf-8") if isinstance(req_body, str) else req_body,
            response_status=resp.get("status", 0),
            response_headers=resp_headers,
            response_body=resp_body.encode("utf-8") if isinstance(resp_body, str) else resp_body,
        ))

    return flows

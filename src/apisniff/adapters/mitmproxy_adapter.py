from __future__ import annotations

import time

from apisniff.adapters import join_header_values
from apisniff.models import CapturedFlow


def _build_headers(headers_obj) -> dict[str, str]:
    grouped: dict[str, list[str]] = {}
    seen: set[str] = set()
    for k, _v in headers_obj.items():
        key = k.lower()
        if key in seen:
            continue
        seen.add(key)
        grouped[key] = headers_obj.get_all(key)
    return join_header_values(grouped)


def flow_to_captured(flow) -> CapturedFlow:
    """Convert a mitmproxy http.HTTPFlow to CapturedFlow."""
    req = flow.request
    res = flow.response

    return CapturedFlow(
        method=req.method,
        host=req.host,
        path=req.path,
        url=req.pretty_url,
        request_headers=_build_headers(req.headers),
        request_body=req.get_content() or b"",
        response_status=res.status_code if res else 0,
        response_headers=_build_headers(res.headers) if res else {},
        response_body=(res.get_content() if res else b"") or b"",
        timestamp=time.time(),
    )

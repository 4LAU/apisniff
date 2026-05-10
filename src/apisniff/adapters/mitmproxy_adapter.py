from __future__ import annotations

import time

from apisniff.models import CapturedFlow


def _build_headers(headers_obj) -> dict[str, str]:
    """Collapse a mitmproxy Headers object into a plain dict.

    Multi-value headers are joined with ", " except set-cookie, which uses "\n".
    """
    result: dict[str, str] = {}
    seen: set[str] = set()
    for k, _v in headers_obj.items():
        key = k.lower()
        if key in seen:
            continue
        seen.add(key)
        values = headers_obj.get_all(key)
        if len(values) == 1:
            result[key] = values[0]
        elif key == "set-cookie":
            result[key] = "\n".join(values)
        else:
            result[key] = ", ".join(values)
    return result


def _build_response_headers(res) -> dict[str, str]:
    return _build_headers(res.headers)


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
        response_headers=_build_response_headers(res) if res else {},
        response_body=(res.get_content() if res else b"") or b"",
        timestamp=time.time(),
    )

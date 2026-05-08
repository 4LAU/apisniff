from __future__ import annotations

import time

from apisniff.models import CapturedFlow


def _build_response_headers(res) -> dict[str, str]:
    headers = {k.lower(): v for k, v in res.headers.items()}
    set_cookies = res.headers.get_all("set-cookie")
    if len(set_cookies) > 1:
        headers["set-cookie"] = "\n".join(set_cookies)
    return headers


def flow_to_captured(flow) -> CapturedFlow:
    """Convert a mitmproxy http.HTTPFlow to CapturedFlow."""
    req = flow.request
    res = flow.response

    return CapturedFlow(
        method=req.method,
        host=req.host,
        path=req.path,
        url=req.pretty_url,
        request_headers={k.lower(): v for k, v in req.headers.items()},
        request_body=req.get_content() or b"",
        response_status=res.status_code if res else 0,
        response_headers=_build_response_headers(res) if res else {},
        response_body=(res.get_content() if res else b"") or b"",
        timestamp=time.time(),
    )

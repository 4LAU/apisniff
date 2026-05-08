from __future__ import annotations

import time

from apisniff.models import CapturedFlow


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
        response_headers={k.lower(): v for k, v in res.headers.items()} if res else {},
        response_body=(res.get_content() if res else b"") or b"",
        timestamp=time.time(),
    )

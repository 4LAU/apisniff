from __future__ import annotations

from pathlib import Path

from apisniff.models import CapturedFlow

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_flow(
    *,
    method: str = "GET",
    host: str = "example.com",
    path: str = "/api/test",
    response_status: int = 200,
    content_type: str = "application/json",
    response_body: bytes = b"{}",
    request_body: bytes = b"",
    request_headers: dict[str, str] | None = None,
    response_headers: dict[str, str] | None = None,
    tags: list[str] | None = None,
    timestamp: float = 0.0,
) -> CapturedFlow:
    """Shared factory for CapturedFlow test instances.

    Builds a valid CapturedFlow with sensible defaults. Override only
    the fields relevant to the test case.
    """
    if request_headers is None:
        request_headers = {}
    resp_hdrs: dict[str, str] = {"content-type": content_type}
    if response_headers is not None:
        resp_hdrs.update(response_headers)

    url = f"https://{host}{path}"
    return CapturedFlow(
        method=method,
        host=host,
        path=path,
        url=url,
        request_headers=request_headers,
        request_body=request_body,
        response_status=response_status,
        response_headers=resp_hdrs,
        response_body=response_body,
        tags=tags if tags is not None else [],
        timestamp=timestamp,
    )

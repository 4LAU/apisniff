from apisniff.auth import AuthPattern, ExtractedCookie
from apisniff.models import CapturedFlow, SessionStats, VendorMatch
from apisniff.report import generate_report


def _flow(
    method="GET",
    host="example.com",
    path="/api/v1/users",
    response_status=200,
    response_headers=None,
    response_body=b'{"ok": true}',
) -> CapturedFlow:
    return CapturedFlow(
        method=method, host=host, path=path,
        url=f"https://{host}{path}", request_headers={},
        request_body=b"", response_status=response_status,
        response_headers=response_headers or {"content-type": "application/json"},
        response_body=response_body,
    )


def test_report_has_all_sections():
    flows = [_flow(), _flow(method="POST", path="/api/v1/users")]
    stats = SessionStats(
        domain="example.com", started_at="2026-05-08T13:00:00",
        duration_seconds=120.0, total_flows=100, kept_flows=2,
        dropped={"static_asset": 50, "third_party": 30, "noise_domain": 18},
    )
    vendors = [VendorMatch(vendor="cloudflare", confidence="high", signals=["cf-ray"])]
    auth_patterns = [AuthPattern(auth_type="bearer", detail="authorization: bearer", flow_count=2)]
    cookies = [ExtractedCookie(name="sid", value="abc", domain="example.com",
                               host_only=True, path="/", secure=False, source="request")]

    report = generate_report(
        domain="example.com", flows=flows, session_stats=stats,
        vendors=vendors, auth_patterns=auth_patterns, cookies=cookies,
    )

    assert "# example.com" in report
    assert "120" in report
    assert "static_asset" in report or "Static" in report
    assert "50" in report
    assert "cloudflare" in report.lower()
    assert "bearer" in report.lower()
    assert "sid" in report
    assert "/api/v1/users" in report


def test_report_without_session_stats():
    flows = [_flow()]
    report = generate_report(
        domain="example.com", flows=flows, session_stats=None,
        vendors=[], auth_patterns=[], cookies=[],
    )
    assert "# example.com" in report
    assert "session stats unavailable" in report.lower()


def test_report_empty_flows():
    report = generate_report(
        domain="example.com", flows=[], session_stats=None,
        vendors=[], auth_patterns=[], cookies=[],
    )
    assert "# example.com" in report
    assert "0" in report

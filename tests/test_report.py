from apisniff.auth import ExtractedCookie
from apisniff.report import generate_report


def test_report_redacts_cookie_values():
    """Cookie values must not appear in report; only names and domains may."""
    cookies = [
        ExtractedCookie(
            name="session_id",
            value="secret_token_abc123",
            domain="example.com",
            host_only=True,
            path="/",
            secure=True,
            source="response",
        ),
        ExtractedCookie(
            name="csrf",
            value="xyzzy_csrf_value",
            domain="example.com",
            host_only=False,
            path="/",
            secure=False,
            source="request",
        ),
    ]

    report = generate_report(
        domain="example.com",
        flows=[],
        session_stats=None,
        vendors=[],
        auth_patterns=[],
        cookies=cookies,
    )

    assert "session_id" in report
    assert "csrf" in report
    assert "secret_token_abc123" not in report
    assert "xyzzy_csrf_value" not in report
    assert "example.com" in report

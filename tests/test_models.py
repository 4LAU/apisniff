"""
Tests for CapturedFlow.content_type, ProbeResult.is_blocked, ProbeResult.is_challenge.

Each test defends a silent failure mode — a bug that would produce wrong classification
output without any crash or visible error.
"""


from apisniff.models import CapturedFlow, ClassifyResult, ProbeResult, SessionStats

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flow(response_headers: dict) -> CapturedFlow:
    return CapturedFlow(
        method="GET",
        host="example.com",
        path="/",
        url="https://example.com/",
        request_headers={},
        request_body=b"",
        response_status=200,
        response_headers=response_headers,
        response_body=b"",
    )


def _result(
    *,
    status: int | None = 200,
    body: bytes = b"ok",
    error: str | None = None,
    headers: dict | None = None,
) -> ProbeResult:
    return ProbeResult(
        label="test",
        status=status,
        headers=headers or {},
        body=body,
        elapsed_ms=10.0,
        error=error,
    )


# ---------------------------------------------------------------------------
# CapturedFlow.content_type
# ---------------------------------------------------------------------------

def test_content_type_strips_charset_parameter():
    # Invariant: charset suffix must be removed — downstream MIME comparisons use
    # exact string equality, so "application/json; charset=utf-8" != "application/json"
    # and the wrong value ships silently.
    flow = _flow({"content-type": "application/json; charset=utf-8"})
    assert flow.content_type == "application/json"


def test_content_type_normalises_to_lowercase():
    # Invariant: mixed-case Content-Type would silently break MIME equality checks
    # because comparisons are case-sensitive.
    flow = _flow({"content-type": "Application/JSON"})
    assert flow.content_type == "application/json"


def test_content_type_missing_header_returns_empty_string():
    # Invariant: absent header must return "" not raise — callers check falsy value
    # to skip content inspection; an exception would surface differently in prod.
    flow = _flow({})
    assert flow.content_type == ""


def test_content_type_header_key_case_insensitive_lookup():
    flow = _flow({"Content-Type": "text/html; charset=utf-8"})
    assert flow.content_type == "text/html"


# ---------------------------------------------------------------------------
# ProbeResult.is_blocked
# ---------------------------------------------------------------------------

def test_is_blocked_true_when_error_set():
    # Invariant: a network error means no response was received; treating it as
    # unblocked would silently report a target as accessible.
    r = _result(error="connection refused", status=None)
    assert r.is_blocked is True


def test_is_blocked_true_when_status_none_no_error():
    # Invariant: status=None without an error string (e.g. timeout with empty
    # response) must still count as blocked — not silently pass as accessible.
    r = _result(status=None, error=None)
    assert r.is_blocked is True


def test_is_blocked_true_for_403():
    r = _result(status=403)
    assert r.is_blocked is True


def test_is_blocked_true_for_429():
    r = _result(status=429)
    assert r.is_blocked is True


def test_is_blocked_true_for_503():
    r = _result(status=503)
    assert r.is_blocked is True


def test_is_blocked_true_for_999():
    # 999 is a Cloudflare-specific block status; missing it silently reports the
    # target as accessible when it is in fact blocked.
    r = _result(status=999)
    assert r.is_blocked is True


def test_is_blocked_false_for_200_clean_body():
    # Invariant: a clean 200 must not be misclassified as blocked.
    r = _result(status=200, body=b"<html>Hello world</html>")
    assert r.is_blocked is False


def test_is_blocked_true_when_challenge_body_despite_200():
    # Invariant: Cloudflare sometimes returns 200 with a JS challenge page;
    # is_blocked must catch this via is_challenge — a silent miss here means the
    # probe reports no protection when there is one.
    body = b"<html>Please wait... <script>_cf_chl_opt={}</script></html>"
    r = _result(status=200, body=body)
    assert r.is_blocked is True


# ---------------------------------------------------------------------------
# ProbeResult.is_challenge
# ---------------------------------------------------------------------------

def test_is_challenge_false_when_error():
    # Invariant: an errored result has no body to inspect; returning True would
    # silently misclassify a connection failure as a JS challenge.
    r = _result(error="timeout", body=b"challenges.cloudflare.com")
    assert r.is_challenge is False


def test_is_challenge_false_when_body_empty():
    # Invariant: empty body must not be treated as a challenge — would silently
    # produce JS_CHALLENGE verdict for any connection that returned no content.
    r = _result(body=b"")
    assert r.is_challenge is False


def test_is_challenge_true_for_each_marker():
    # Invariant: each distinct marker must trigger detection independently;
    # a typo in _CHALLENGE_MARKERS would silently miss that challenge variant.
    markers = [
        b"challenges.cloudflare.com",
        b"challenge-platform",
        b"managed_challenge",
        b"jschl_vc",
        b"_cf_chl_opt",
        b"cf-please-wait",
    ]
    for marker in markers:
        r = _result(body=b"<html>" + marker + b"</html>")
        assert r.is_challenge is True, f"marker {marker!r} not detected"


def test_is_challenge_case_insensitive():
    # Invariant: body is lowercased before matching; an uppercase marker in the
    # wild (e.g. "CF-Please-Wait") must still be detected — a miss silently
    # bypasses the challenge classification.
    r = _result(body=b"<html>CF-Please-Wait</html>")
    assert r.is_challenge is True


def test_is_challenge_only_inspects_first_50000_bytes():
    # Invariant: the 50 000-byte cap means a marker beyond that limit is silently
    # ignored. The test confirms truncation happens AND that content before the
    # cap is still matched — both halves of the contract.
    padding = b"x" * 50_000
    marker_before_cap = b"cf-please-wait" + padding
    marker_after_cap = padding + b"cf-please-wait"

    assert _result(body=marker_before_cap).is_challenge is True
    assert _result(body=marker_after_cap).is_challenge is False


# ---------------------------------------------------------------------------
# ClassifyResult
# ---------------------------------------------------------------------------

def test_classify_result_keep():
    flow = CapturedFlow(
        method="GET", host="example.com", path="/api/users",
        url="https://example.com/api/users", request_headers={},
        request_body=b"", response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"ok": true}',
    )
    result = ClassifyResult(action="keep", category="", flow=flow)
    assert result.action == "keep"
    assert result.flow is not None
    assert result.flow.host == "example.com"


def test_classify_result_drop():
    result = ClassifyResult(action="drop", category="static_asset", flow=None)
    assert result.action == "drop"
    assert result.category == "static_asset"
    assert result.flow is None


# ---------------------------------------------------------------------------
# SessionStats
# ---------------------------------------------------------------------------

def test_session_stats_roundtrip():
    stats = SessionStats(
        domain="example.com",
        started_at="2026-05-08T13:00:00",
        duration_seconds=120.5,
        total_flows=450,
        kept_flows=85,
        dropped={"static_asset": 200, "third_party": 100, "noise_domain": 40,
                 "same_site_noise": 15, "path_telemetry": 10},
    )
    d = stats.to_dict()
    assert d["domain"] == "example.com"
    assert d["kept_flows"] == 85
    assert d["dropped"]["static_asset"] == 200

    restored = SessionStats.from_dict(d)
    assert restored == stats


def test_session_stats_from_dict_missing_fields():
    d = {"domain": "example.com", "started_at": "2026-05-08T13:00:00",
         "duration_seconds": 10.0, "total_flows": 5, "kept_flows": 3, "dropped": {}}
    stats = SessionStats.from_dict(d)
    assert stats.dropped == {}

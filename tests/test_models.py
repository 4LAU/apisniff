"""
Tests for CapturedFlow.content_type, ProbeResult.is_blocked, ProbeResult.is_challenge,
body serialization roundtrip, normalize_path, and replay_dedup_key.

Each test defends a silent failure mode — a bug that would produce wrong classification
output without any crash or visible error.
"""


from apisniff.models import (
    CapturedFlow,
    ClassifyResult,
    ProbeResult,
    ReplayResult,
    SessionStats,
    normalize_path,
    replay_dedup_key,
)

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


# ---------------------------------------------------------------------------
# CapturedFlow body serialization roundtrip (base64)
# ---------------------------------------------------------------------------

def _base_flow(request_body: bytes = b"", response_body: bytes = b"") -> CapturedFlow:
    return CapturedFlow(
        method="POST",
        host="example.com",
        path="/api/upload",
        url="https://example.com/api/upload",
        request_headers={"content-type": "application/octet-stream"},
        request_body=request_body,
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=response_body,
    )


def test_body_serialization_binary_roundtrip():
    # Invariant: binary data that cannot be losslessly decoded as UTF-8 must
    # survive to_dict() → from_dict() without corruption. The old utf-8/replace
    # path silently mangled non-UTF-8 bytes.
    binary = bytes(range(256))
    flow = _base_flow(request_body=binary, response_body=binary)
    d = flow.to_dict()
    assert d.get("_body_encoding") == "base64"
    restored = CapturedFlow.from_dict(d)
    assert restored.request_body == binary
    assert restored.response_body == binary


def test_body_serialization_empty_bodies():
    # Invariant: empty bodies (None sentinel in dict) must come back as b"" not
    # raise an exception during base64 decode.
    flow = _base_flow(request_body=b"", response_body=b"")
    d = flow.to_dict()
    assert d["request_body"] is None
    assert d["response_body"] is None
    restored = CapturedFlow.from_dict(d)
    assert restored.request_body == b""
    assert restored.response_body == b""


def test_body_serialization_utf8_ascii_roundtrip():
    # Invariant: normal JSON bodies (valid UTF-8) must also roundtrip correctly
    # through the base64 path.
    payload = b'{"key": "value", "num": 42}'
    flow = _base_flow(request_body=payload, response_body=payload)
    restored = CapturedFlow.from_dict(flow.to_dict())
    assert restored.request_body == payload
    assert restored.response_body == payload


def test_body_serialization_legacy_format_no_marker():
    # Invariant: JSONL files written before the base64 change (no _body_encoding
    # key) must still load correctly via the str.encode("utf-8") fallback path.
    d = {
        "method": "GET",
        "host": "example.com",
        "path": "/legacy",
        "url": "https://example.com/legacy",
        "request_headers": {},
        "request_body": "hello legacy",
        "response_status": 200,
        "response_headers": {},
        "response_body": '{"ok": true}',
        "tags": [],
        "timestamp": 0.0,
        # No "_body_encoding" key — legacy format
    }
    flow = CapturedFlow.from_dict(d)
    assert flow.request_body == b"hello legacy"
    assert flow.response_body == b'{"ok": true}'


def test_body_serialization_to_jsonl_roundtrip():
    # Invariant: to_jsonl() → from_dict() must produce an identical CapturedFlow,
    # including non-ASCII bytes.
    import json
    binary = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    flow = _base_flow(request_body=binary, response_body=binary)
    jsonl = flow.to_jsonl()
    restored = CapturedFlow.from_dict(json.loads(jsonl))
    assert restored.request_body == binary
    assert restored.response_body == binary


# ---------------------------------------------------------------------------
# normalize_path (moved from spec.py to models.py)
# ---------------------------------------------------------------------------

def test_normalize_path_uuid():
    assert normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000") == "/api/users/{id}"


def test_normalize_path_numeric():
    assert normalize_path("/api/users/12345") == "/api/users/{id}"


def test_normalize_path_hex():
    # 16+ hex chars are treated as IDs
    assert normalize_path("/api/objects/deadbeefcafe0000") == "/api/objects/{id}"


def test_normalize_path_no_dynamic_segment():
    assert normalize_path("/api/users") == "/api/users"


def test_normalize_path_strips_query_string():
    # query string must be ignored — normalize_path only handles the path portion
    assert normalize_path("/api/users/42?foo=bar") == "/api/users/{id}"


def test_normalize_path_preserves_static_segments():
    assert normalize_path("/api/v1/search") == "/api/v1/search"


def test_normalize_path_multiple_dynamic_segments():
    assert normalize_path("/orgs/99/repos/abc-def-ghi") == "/orgs/{id}/repos/abc-def-ghi"


# ---------------------------------------------------------------------------
# replay_dedup_key
# ---------------------------------------------------------------------------

def test_replay_dedup_key_no_query_string_equals_normalize_path():
    # Invariant: paths without query strings must produce the same key as
    # normalize_path() — dedup logic must not add extra structure.
    path = "/api/users/12345"
    assert replay_dedup_key(path) == normalize_path(path)


def test_replay_dedup_key_same_keys_different_values_dedup_together():
    # Invariant: two requests with the same param names but different values
    # must produce the same key — value divergence is not part of the dedup key.
    key1 = replay_dedup_key("/search?q=apple&page=1")
    key2 = replay_dedup_key("/search?q=banana&page=99")
    assert key1 == key2


def test_replay_dedup_key_different_keys_dont_dedup():
    # Invariant: requests with different query parameter *names* must produce
    # different keys — merging them would collapse structurally distinct calls.
    key1 = replay_dedup_key("/search?q=apple")
    key2 = replay_dedup_key("/search?query=apple")
    assert key1 != key2


def test_replay_dedup_key_sorts_query_params():
    # Invariant: param order must not affect the key — param ordering varies
    # across clients and is not semantically meaningful.
    key1 = replay_dedup_key("/search?page=1&q=test")
    key2 = replay_dedup_key("/search?q=test&page=1")
    assert key1 == key2


def test_replay_dedup_key_normalizes_path_segment():
    # Invariant: dynamic path segments must be normalized even when a query
    # string is also present.
    key = replay_dedup_key("/api/users/12345?include=details")
    assert key == "/api/users/{id}?include={v}"


def test_replay_dedup_key_empty_query_string_acts_like_no_qs():
    # Edge case: a trailing "?" with no params should not add "?" to the key.
    key_with = replay_dedup_key("/api/users?")
    key_without = replay_dedup_key("/api/users")
    # Both should normalize the path; with empty qs parse_qs returns {} so no
    # query portion is appended.
    assert key_with == key_without

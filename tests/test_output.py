import json

from apisniff.models import (
    CapturedFlow,
    ProbeAssessment,
    ProbeResult,
    ProbeVerdict,
    ReplayResult,
    VendorMatch,
)
from apisniff.output import (
    probe_to_dict,
    probe_to_json,
    replay_to_json,
)


def _assessment() -> ProbeAssessment:
    return ProbeAssessment(
        url="https://example.com",
        verdict=ProbeVerdict.CLIENT_DEPENDENT,
        recommendation="Use curl_cffi with Chrome profile.",
        results={
            "naked": ProbeResult("naked", 403, {}, b"blocked", 150.0, None),
            "impersonated": ProbeResult("impersonated", 200, {}, b"ok", 90.0, None),
            "tls_only": ProbeResult("tls_only", 200, {}, b"ok", 95.0, None),
        },
        vendors=[VendorMatch("cloudflare", "high", ["header_present:cf-ray"])],
        graphql_endpoints=["/graphql"],
        graphql_introspection=True,
    )


def test_probe_to_dict():
    d = probe_to_dict(_assessment())
    assert d["url"] == "https://example.com"
    assert d["verdict"] == "client_dependent"
    assert d["recommendation"] == "Use curl_cffi with Chrome profile."
    assert len(d["vendors"]) == 1
    assert d["vendors"][0]["vendor"] == "cloudflare"
    assert d["probes"]["naked"]["status"] == 403
    assert d["probes"]["impersonated"]["status"] == 200
    assert d["graphql"]["endpoints"] == ["/graphql"]
    assert d["graphql"]["introspection"] is True


def test_probe_to_json():
    j = probe_to_json(_assessment())
    parsed = json.loads(j)
    assert parsed["verdict"] == "client_dependent"


# ---------------------------------------------------------------------------
# Replay output helpers
# ---------------------------------------------------------------------------

def _flow(
    method: str = "GET",
    path: str = "/api/v1/users",
    status: int = 200,
    request_headers: dict | None = None,
    timestamp: float = 1_746_709_320.0,  # 2026-05-08T13:02:00Z approx
) -> CapturedFlow:
    return CapturedFlow(
        method=method,
        host="example.com",
        path=path,
        url=f"https://example.com{path}",
        request_headers=request_headers or {},
        request_body=b"",
        response_status=status,
        response_headers={},
        response_body=b"",
        timestamp=timestamp,
    )


def _result(
    category: str = "match",
    path: str = "/api/v1/users",
    original_status: int = 200,
    replayed_status: int = 200,
    elapsed_ms: float = 12.0,
    body_shape_diff: dict | None = None,
) -> ReplayResult:
    return ReplayResult(
        original_flow=_flow(path=path, status=original_status),
        replayed_status=replayed_status,
        elapsed_ms=elapsed_ms,
        error=None,
        category=category,  # type: ignore[arg-type]
        status_match=(original_status == replayed_status),
        body_shape_match=(body_shape_diff is None),
        body_shape_diff=body_shape_diff,
        size_original=100,
        size_replayed=100 if body_shape_diff is None else 90,
    )


def test_replay_to_json_structure():
    results = [
        _result("match"),
        _result("blocked", path="/api/v1/orders", original_status=200, replayed_status=403),
    ]
    raw = replay_to_json(results, "example.com")
    data = json.loads(raw)

    assert data["domain"] == "example.com"
    assert "replayed_at" in data
    assert len(data["endpoints"]) == 2
    assert "summary" in data


def test_replay_to_json_endpoint_fields():
    results = [_result("match", elapsed_ms=12.3)]
    data = json.loads(replay_to_json(results, "example.com"))
    ep = data["endpoints"][0]

    assert ep["method"] == "GET"
    assert ep["path"] == "/api/v1/users"
    assert ep["original_status"] == 200
    assert ep["replayed_status"] == 200
    assert ep["category"] == "match"
    assert ep["body_shape_diff"] is None
    assert ep["elapsed_ms"] == 12.3


def test_replay_to_json_summary_counts():
    results = [
        _result("match"),
        _result("match"),
        _result("drift", body_shape_diff={"x": {"was": "int", "now": "str"}}),
        _result("auth_expired", replayed_status=401),
        _result("blocked", replayed_status=403),
    ]
    data = json.loads(replay_to_json(results, "example.com"))
    s = data["summary"]
    assert s["match"] == 2
    assert s["drift"] == 1
    assert s["auth_expired"] == 1
    assert s["blocked"] == 1
    assert s["error"] == 0


def test_replay_to_json_drift_diff_preserved():
    diff = {"data.x": {"was": None, "now": "str"}, "data.y": {"was": "str", "now": None}}
    results = [_result("drift", body_shape_diff=diff)]
    data = json.loads(replay_to_json(results, "example.com"))
    assert data["endpoints"][0]["body_shape_diff"] == diff


def test_replay_to_json_replayed_at_format():
    data = json.loads(replay_to_json([], "example.com"))
    ts = data["replayed_at"]
    # Should be ISO 8601 ending in Z
    assert ts.endswith("Z")
    assert "T" in ts

# tests/test_probe.py
from apisniff.models import ProbeResult, ProbeVerdict
from apisniff.probe import classify_results


def _result(label, status=200, headers=None, body=b"<html>ok</html>", elapsed_ms=100.0, error=None):
    return ProbeResult(
        label=label,
        status=status,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def test_classify_all_200():
    results = {
        "naked": _result("naked"),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.NO_PROTECTION
    assert "raw HTTP" in recommendation.lower() or "no active" in recommendation.lower()


def test_classify_naked_blocked_others_pass():
    results = {
        "naked": _result("naked", status=403),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT
    assert "curl_cffi" in recommendation.lower() or "impersonat" in recommendation.lower()


def test_classify_naked_and_tls_blocked():
    results = {
        "naked": _result("naked", status=403),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only", status=403),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT


def test_classify_all_blocked():
    results = {
        "naked": _result("naked", status=403),
        "impersonated": _result("impersonated", status=403),
        "tls_only": _result("tls_only", status=403),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.FULL_BLOCK


def test_classify_all_challenge():
    results = {
        "naked": _result("naked", body=b"challenges.cloudflare.com"),
        "impersonated": _result("impersonated", body=b"challenges.cloudflare.com"),
        "tls_only": _result("tls_only", body=b"challenges.cloudflare.com"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict in (ProbeVerdict.JS_CHALLENGE, ProbeVerdict.FULL_BLOCK)


def test_classify_naked_challenge_impersonated_pass():
    results = {
        "naked": _result("naked", body=b"challenges.cloudflare.com"),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT

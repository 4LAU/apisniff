# tests/test_probe.py
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apisniff.models import ProbeResult, ProbeVerdict, VendorMatch
from apisniff.probe import _probe_curl_cffi, classify_results, fetch_graphql_schema, run_probes


@pytest.mark.asyncio
async def test_fetch_graphql_schema_success():
    mock_schema = {
        "data": {
            "__schema": {
                "types": [{"name": "Query"}, {"name": "User"}, {"name": "Post"}],
            }
        }
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_schema

    with patch("apisniff.probe.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await fetch_graphql_schema("https://example.com/graphql")
        assert result is not None
        assert "__schema" in result["data"]
        assert len(result["data"]["__schema"]["types"]) == 3


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
    assert "no active" in recommendation.lower()


def test_classify_all_200_with_vendors():
    results = {
        "naked": _result("naked"),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    vendors = [VendorMatch(vendor="akamai", confidence="medium", signals=["header_present:akamai-grn"])]
    verdict, recommendation = classify_results(results, vendors)
    assert verdict == ProbeVerdict.NO_PROTECTION
    assert "akamai" in recommendation.lower()
    assert "not enforcing" in recommendation.lower()


def test_classify_naked_blocked_others_pass():
    results = {
        "naked": _result("naked", status=403),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT
    assert "tls" in recommendation.lower() or "browser" in recommendation.lower()


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
    assert verdict == ProbeVerdict.JS_CHALLENGE


def test_classify_naked_challenge_impersonated_pass():
    results = {
        "naked": _result("naked", body=b"challenges.cloudflare.com"),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT


@pytest.mark.asyncio
async def test_probe_curl_cffi_impersonate_threaded(monkeypatch):
    """Verify impersonate parameter reaches curl_cffi session."""
    captured_impersonate = {}

    class FakeResp:
        status_code = 200
        headers = {}
        content = b"ok"

    class FakeSession:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            pass
        async def get(self, url, **kwargs):
            captured_impersonate["value"] = kwargs.get("impersonate")
            return FakeResp()

    monkeypatch.setattr("curl_cffi.requests.AsyncSession", FakeSession)
    await _probe_curl_cffi("https://example.com", "test", "ua", impersonate="safari17_0")
    assert captured_impersonate["value"] == "safari17_0"


@pytest.mark.asyncio
async def test_run_probes_impersonate_parameter(monkeypatch):
    """run_probes passes impersonate to curl_cffi probes."""
    calls = []

    async def fake_curl(url, label, ua, headers=None, proxy=None, impersonate="chrome"):
        calls.append({"label": label, "impersonate": impersonate})
        return ProbeResult(
            label=label, status=200, headers={}, body=b"",
            elapsed_ms=1.0, error=None,
        )

    async def fake_httpx(url, label, ua, headers=None, proxy=None):
        return ProbeResult(
            label=label, status=200, headers={}, body=b"",
            elapsed_ms=1.0, error=None,
        )

    monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_curl)
    monkeypatch.setattr("apisniff.probe._probe_httpx", fake_httpx)
    monkeypatch.setattr("apisniff.probe.load_signatures", lambda: {})
    monkeypatch.setattr("apisniff.probe.match_vendors", lambda *a: [])

    await run_probes("https://example.com", skip_graphql=True, impersonate="safari17_0")

    curl_calls = [c for c in calls if c["label"] in ("impersonated", "tls_only")]
    assert all(c["impersonate"] == "safari17_0" for c in curl_calls)

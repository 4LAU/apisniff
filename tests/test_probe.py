# tests/test_probe.py
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apisniff.models import ProbeAssessment, ProbeResult, ProbeVerdict, VendorMatch
from apisniff.output import probe_to_dict, probe_to_json
from apisniff.probe import (
    _probe_curl_cffi,
    _probe_httpx,
    classify_results,
    fetch_graphql_schema,
)


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
        assert mock_client_cls.call_args.kwargs["verify"] is True


@pytest.mark.asyncio
async def test_fetch_graphql_schema_insecure_disables_tls_verification():
    with patch("apisniff.probe.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = MagicMock(status_code=404)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        await fetch_graphql_schema("https://example.com/graphql", insecure=True)

        assert mock_client_cls.call_args.kwargs["verify"] is False


def _result(label, status=200, headers=None, body=b"<html>ok</html>", elapsed_ms=100.0, error=None):
    return ProbeResult(
        label=label,
        status=status,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def _probe_assessment(
    verdict=ProbeVerdict.NO_PROTECTION,
    vendors=None,
    results=None,
) -> ProbeAssessment:
    return ProbeAssessment(
        url="https://example.com/path",
        verdict=verdict,
        recommendation="Use the recommended client.",
        results=results or {
            "naked": _result("naked"),
            "impersonated": _result("impersonated"),
            "tls_only": _result("tls_only"),
        },
        vendors=vendors or [],
    )


def test_probe_to_dict_includes_self_describing_fields():
    data = probe_to_dict(_probe_assessment())

    assert data["schema_version"] == 1
    assert data["interpretation"] == (
        "No active defenses on example.com — raw HTTP requests work."
    )
    assert data["probe_descriptions"] == {
        "naked": "Raw HTTP client, bot user-agent — tests baseline bot detection",
        "impersonated": (
            "Chrome TLS fingerprint + Chrome user-agent — "
            "tests if browser impersonation works"
        ),
        "tls_only": (
            "Chrome TLS fingerprint, bot user-agent — "
            "isolates whether detection is TLS-based or UA-based"
        ),
    }
    assert data["verdict_descriptions"]["client_dependent"] == (
        "Detection based on TLS fingerprint or user-agent — "
        "browser impersonation bypasses it"
    )


def test_probe_to_json_includes_probe_to_dict_enrichment():
    data = json.loads(probe_to_json(_probe_assessment()))

    assert data["schema_version"] == 1
    assert "interpretation" in data
    assert "probe_descriptions" in data
    assert "verdict_descriptions" in data


def test_probe_interpretation_includes_vendor_passthrough():
    data = probe_to_dict(
        _probe_assessment(vendors=[VendorMatch("cloudflare", "high", ["cf-ray"])])
    )

    assert data["interpretation"] == (
        "Cloudflare detected on example.com but not enforcing — "
        "raw HTTP requests work."
    )


def test_probe_interpretation_describes_client_dependent_takeaway():
    data = probe_to_dict(
        _probe_assessment(
            verdict=ProbeVerdict.CLIENT_DEPENDENT,
            results={
                "naked": _result("naked", status=403),
                "impersonated": _result("impersonated"),
                "tls_only": _result("tls_only"),
            },
        )
    )

    assert data["interpretation"] == (
        "example.com filters by TLS fingerprint — "
        "browser impersonation required, raw clients blocked."
    )


def test_probe_interpretation_describes_challenge_and_full_block():
    challenge = probe_to_dict(
        _probe_assessment(
            verdict=ProbeVerdict.JS_CHALLENGE,
            vendors=[VendorMatch("cloudflare", "high", ["challenge"])],
        )
    )
    blocked = probe_to_dict(_probe_assessment(verdict=ProbeVerdict.FULL_BLOCK))

    assert challenge["interpretation"] == (
        "Cloudflare JS challenge on example.com — requires a real browser session."
    )
    assert blocked["interpretation"] == (
        "example.com blocks all automated access — manual browser session required."
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


def test_classify_naked_blocked_others_pass():
    results = {
        "naked": _result("naked", status=403),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT
    assert "tls" in recommendation.lower() or "browser" in recommendation.lower()


def test_classify_impersonated_blocked_others_pass():
    results = {
        "naked": _result("naked"),
        "impersonated": _result("impersonated", status=403),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT
    assert "browser user-agent" in recommendation.lower() or "javascript" in recommendation.lower()


def test_classify_impersonated_and_tls_blocked_naked_pass():
    results = {
        "naked": _result("naked"),
        "impersonated": _result("impersonated", status=403),
        "tls_only": _result("tls_only", status=403),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT
    assert "impersonat" in recommendation.lower() or "browser tls" in recommendation.lower()


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
async def test_probe_httpx_verifies_tls_by_default():
    with patch("apisniff.probe.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get.return_value = MagicMock(status_code=200, headers={}, content=b"ok")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        await _probe_httpx("https://example.com", "test", "ua")

        assert mock_client_cls.call_args.kwargs["verify"] is True


@pytest.mark.asyncio
async def test_probe_curl_cffi_insecure_disables_tls_verification(monkeypatch):
    captured = {}

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
            captured["verify"] = kwargs.get("verify")
            return FakeResp()

    monkeypatch.setattr("curl_cffi.requests.AsyncSession", FakeSession)
    await _probe_curl_cffi("https://example.com", "test", "ua", insecure=True)
    assert captured["verify"] is False

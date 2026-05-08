# tests/test_probe.py
from unittest.mock import AsyncMock, patch

import pytest

from apisniff.models import ProbeResult, ProbeVerdict
from apisniff.probe import classify_results, fetch_graphql_schema


@pytest.mark.asyncio
async def test_fetch_graphql_schema_success():
    mock_schema = {
        "data": {
            "__schema": {
                "types": [{"name": "Query"}, {"name": "User"}, {"name": "Post"}],
            }
        }
    }

    mock_response = AsyncMock()
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


@pytest.mark.asyncio
async def test_fetch_graphql_schema_failure():
    with patch("apisniff.probe.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await fetch_graphql_schema("https://example.com/graphql")
        assert result is None


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
    assert verdict == ProbeVerdict.JS_CHALLENGE


def test_classify_naked_challenge_impersonated_pass():
    results = {
        "naked": _result("naked", body=b"challenges.cloudflare.com"),
        "impersonated": _result("impersonated"),
        "tls_only": _result("tls_only"),
    }
    verdict, recommendation = classify_results(results)
    assert verdict == ProbeVerdict.CLIENT_DEPENDENT

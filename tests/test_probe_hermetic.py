"""Hermetic probe tests — monkeypatched HTTP, no network access.

Covers gaps not addressed by test_probe.py, test_vendors.py, or test_rate_limit.py:
- Full run_probes() pipeline with monkeypatched HTTP clients
- Vendor detection from specific body/cookie patterns (distinct from header-only tests)
- Rate limit edge cases (503, immediate 429)
- Edge cases in classify_results not covered by existing tests
"""
from __future__ import annotations

import pytest

from apisniff.models import ProbeResult, ProbeVerdict, RateLimitResult, VendorMatch
from apisniff.probe import classify_results, probe_rate_limit, run_probes
from apisniff.vendors import load_signatures, match_vendors

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(
    label: str,
    status: int = 200,
    headers: dict | None = None,
    body: bytes = b"<html>ok</html>",
    elapsed_ms: float = 100.0,
    error: str | None = None,
) -> ProbeResult:
    return ProbeResult(
        label=label,
        status=status,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
        error=error,
    )


# ---------------------------------------------------------------------------
# run_probes: full pipeline with monkeypatched clients
# ---------------------------------------------------------------------------

class TestRunProbesHermetic:
    """Monkeypatch both HTTP clients to test the full probe pipeline."""

    @pytest.mark.asyncio
    async def test_all_200_returns_no_protection(self, monkeypatch):
        async def fake_httpx(url, label, ua, headers=None, proxy=None, insecure=False):
            return _result(label, status=200)

        async def fake_curl(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            return _result(label, status=200)

        monkeypatch.setattr("apisniff.probe._probe_httpx", fake_httpx)
        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_curl)

        assessment = await run_probes("https://example.com", skip_graphql=True)

        assert assessment.verdict == ProbeVerdict.NO_PROTECTION
        assert assessment.url == "https://example.com"
        assert "naked" in assessment.results
        assert "impersonated" in assessment.results
        assert "tls_only" in assessment.results

    @pytest.mark.asyncio
    async def test_all_403_returns_full_block(self, monkeypatch):
        async def fake_httpx(url, label, ua, headers=None, proxy=None, insecure=False):
            return _result(label, status=403)

        async def fake_curl(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            return _result(label, status=403)

        monkeypatch.setattr("apisniff.probe._probe_httpx", fake_httpx)
        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_curl)

        assessment = await run_probes("https://blocked.com", skip_graphql=True)

        assert assessment.verdict == ProbeVerdict.FULL_BLOCK

    @pytest.mark.asyncio
    async def test_naked_blocked_others_pass_returns_client_dependent(self, monkeypatch):
        async def fake_httpx(url, label, ua, headers=None, proxy=None, insecure=False):
            return _result(label, status=403)  # naked uses httpx

        async def fake_curl(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            return _result(label, status=200)

        monkeypatch.setattr("apisniff.probe._probe_httpx", fake_httpx)
        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_curl)

        assessment = await run_probes("https://example.com", skip_graphql=True)

        assert assessment.verdict == ProbeVerdict.CLIENT_DEPENDENT

    @pytest.mark.asyncio
    async def test_all_challenge_returns_js_challenge(self, monkeypatch):
        challenge_body = b"<html>challenges.cloudflare.com</html>"

        async def fake_httpx(url, label, ua, headers=None, proxy=None, insecure=False):
            return _result(label, status=200, body=challenge_body)

        async def fake_curl(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            return _result(label, status=200, body=challenge_body)

        monkeypatch.setattr("apisniff.probe._probe_httpx", fake_httpx)
        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_curl)

        assessment = await run_probes("https://cf.example.com", skip_graphql=True)

        assert assessment.verdict == ProbeVerdict.JS_CHALLENGE

    @pytest.mark.asyncio
    async def test_url_auto_prefixed_with_https(self, monkeypatch):
        captured_urls = []

        async def fake_httpx(url, label, ua, headers=None, proxy=None, insecure=False):
            captured_urls.append(url)
            return _result(label, status=200)

        async def fake_curl(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            captured_urls.append(url)
            return _result(label, status=200)

        monkeypatch.setattr("apisniff.probe._probe_httpx", fake_httpx)
        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_curl)

        await run_probes("example.com", skip_graphql=True)

        assert all(u.startswith("https://") for u in captured_urls)

    @pytest.mark.asyncio
    async def test_probe_rate_enabled(self, monkeypatch):
        async def fake_httpx(url, label, ua, headers=None, proxy=None, insecure=False):
            return _result(label, status=200)

        async def fake_curl(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            return _result(label, status=200)

        monkeypatch.setattr("apisniff.probe._probe_httpx", fake_httpx)
        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_curl)

        assessment = await run_probes(
            "https://example.com",
            skip_graphql=True,
            probe_rate=True,
        )

        assert assessment.rate_limit is not None
        assert isinstance(assessment.rate_limit, RateLimitResult)


# ---------------------------------------------------------------------------
# Vendor detection: distinct signals not covered by test_vendors.py
# ---------------------------------------------------------------------------

class TestVendorDetectionHermetic:
    """Vendor detection using real signatures with canned responses."""

    def test_cloudflare_detected_from_challenge_body(self):
        sigs = load_signatures()
        results = [
            _result("naked", body=b"<html>challenges.cloudflare.com</html>"),
        ]
        vendors = match_vendors(results, sigs)
        vendor_names = [v.vendor for v in vendors]
        assert "cloudflare" in vendor_names
        cf = next(v for v in vendors if v.vendor == "cloudflare")
        assert cf.confidence == "high"

    def test_akamai_detected_from_abck_cookie(self):
        sigs = load_signatures()
        results = [
            _result(
                "naked",
                headers={"set-cookie": "_abck=xyz123; path=/"},
            ),
        ]
        vendors = match_vendors(results, sigs)
        vendor_names = [v.vendor for v in vendors]
        assert "akamai" in vendor_names


# ---------------------------------------------------------------------------
# classify_results: edge cases not covered by test_probe.py
# ---------------------------------------------------------------------------

class TestClassifyEdgeCases:
    """Edge cases in verdict classification."""

    def test_error_in_naked_probe_counts_as_blocked(self):
        results = {
            "naked": _result("naked", error="ConnectionError: refused"),
            "impersonated": _result("impersonated", status=200),
            "tls_only": _result("tls_only", status=200),
        }
        verdict, _ = classify_results(results)
        assert verdict == ProbeVerdict.CLIENT_DEPENDENT

    def test_all_errors_is_full_block(self):
        results = {
            "naked": _result("naked", error="timeout"),
            "impersonated": _result("impersonated", error="timeout"),
            "tls_only": _result("tls_only", error="timeout"),
        }
        verdict, _ = classify_results(results)
        assert verdict == ProbeVerdict.FULL_BLOCK

    def test_status_none_treated_as_blocked(self):
        results = {
            "naked": ProbeResult(
                label="naked", status=None, headers={},
                body=b"", elapsed_ms=100, error="DNS failure",
            ),
            "impersonated": _result("impersonated", status=200),
            "tls_only": _result("tls_only", status=200),
        }
        verdict, _ = classify_results(results)
        assert verdict == ProbeVerdict.CLIENT_DEPENDENT

    def test_999_status_is_blocked(self):
        """LinkedIn-style 999 status should count as blocked."""
        results = {
            "naked": _result("naked", status=999),
            "impersonated": _result("impersonated", status=200),
            "tls_only": _result("tls_only", status=200),
        }
        verdict, _ = classify_results(results)
        assert verdict == ProbeVerdict.CLIENT_DEPENDENT

    def test_naked_and_tls_challenged_impersonated_passes(self):
        """Mixed challenge: only impersonated passes."""
        results = {
            "naked": _result("naked", body=b"challenges.cloudflare.com"),
            "impersonated": _result("impersonated", status=200),
            "tls_only": _result("tls_only", body=b"challenges.cloudflare.com"),
        }
        verdict, _ = classify_results(results)
        assert verdict == ProbeVerdict.CLIENT_DEPENDENT

    def test_vendors_included_in_recommendation(self):
        results = {
            "naked": _result("naked", status=403),
            "impersonated": _result("impersonated", status=200),
            "tls_only": _result("tls_only", status=200),
        }
        vendors = [VendorMatch("cloudflare", "high", ["cf-ray"])]
        verdict, recommendation = classify_results(results, vendors)
        assert verdict == ProbeVerdict.CLIENT_DEPENDENT
        assert "Cloudflare" in recommendation


# ---------------------------------------------------------------------------
# Rate limit detection: edge cases not covered by test_rate_limit.py
# ---------------------------------------------------------------------------

class TestRateLimitHermetic:
    """Rate limit edge cases: 503 status and immediate 429."""

    @pytest.mark.asyncio
    async def test_503_counts_as_rate_limit(self, monkeypatch):
        call_count = 0

        async def fake_probe(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            nonlocal call_count
            call_count += 1
            status = 503 if call_count > 5 else 200
            return _result(label, status=status, elapsed_ms=50.0)

        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_probe)
        result = await probe_rate_limit("https://example.com", count=20)
        assert result.first_block_at == 6
        assert result.block_status == 503

    @pytest.mark.asyncio
    async def test_immediate_429_on_first_request(self, monkeypatch):
        async def fake_probe(
            url, label, ua, headers=None, proxy=None,
            impersonate="chrome", insecure=False,
        ):
            return _result(
                label, status=429,
                headers={"retry-after": "60"},
                elapsed_ms=10.0,
            )

        monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_probe)
        result = await probe_rate_limit("https://example.com", count=10)
        assert result.first_block_at == 1
        assert result.retry_after == "60"
        assert result.requests_sent == 1

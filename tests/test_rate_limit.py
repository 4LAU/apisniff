import pytest

from apisniff.models import ProbeResult


@pytest.mark.asyncio
async def test_probe_rate_limit_detects_429(monkeypatch):
    """Rate limit probe detects 429 responses."""
    call_count = 0

    async def fake_probe(
        url, label, ua, headers=None, proxy=None, impersonate="chrome", insecure=False,
    ):
        nonlocal call_count
        call_count += 1
        status = 429 if call_count > 10 else 200
        return ProbeResult(
            label=label, status=status,
            headers={"retry-after": "30"} if status == 429 else {},
            body=b"", elapsed_ms=100.0, error=None,
        )

    monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_probe)
    from apisniff.probe import probe_rate_limit
    result = await probe_rate_limit("https://example.com", count=20)
    assert result.first_block_at == 11
    assert result.block_status == 429
    assert result.retry_after == "30"


@pytest.mark.asyncio
async def test_probe_rate_limit_no_block(monkeypatch):
    """Rate limit probe reports no block when all requests succeed."""
    async def fake_probe(
        url, label, ua, headers=None, proxy=None, impersonate="chrome", insecure=False,
    ):
        return ProbeResult(
            label=label, status=200, headers={},
            body=b"", elapsed_ms=100.0, error=None,
        )

    monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_probe)
    from apisniff.probe import probe_rate_limit
    result = await probe_rate_limit("https://example.com", count=10)
    assert result.first_block_at is None
    assert result.block_status is None


@pytest.mark.asyncio
async def test_probe_rate_limit_detects_silent_throttle(monkeypatch):
    """Detects silent throttle when second half is >2x slower."""
    call_count = 0

    async def fake_probe(
        url, label, ua, headers=None, proxy=None, impersonate="chrome", insecure=False,
    ):
        nonlocal call_count
        call_count += 1
        ms = 100.0 if call_count <= 10 else 500.0
        return ProbeResult(
            label=label, status=200, headers={},
            body=b"", elapsed_ms=ms, error=None,
        )

    monkeypatch.setattr("apisniff.probe._probe_curl_cffi", fake_probe)
    from apisniff.probe import probe_rate_limit
    result = await probe_rate_limit("https://example.com", count=20)
    assert result.silent_throttle is True

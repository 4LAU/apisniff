"""Live smoke tests — gated by APISNIFF_LIVE=1 environment variable.

These are confidence checks against real endpoints, NOT a release gate.
Skipped in CI by default. Run with:
    APISNIFF_LIVE=1 uv run pytest tests/test_live_smoke.py -v
"""
from __future__ import annotations

import os

import pytest

from apisniff.models import ProbeAssessment, ProbeVerdict

live = pytest.mark.skipif(
    not os.environ.get("APISNIFF_LIVE"),
    reason="live tests disabled — set APISNIFF_LIVE=1 to enable",
)


@live
@pytest.mark.asyncio
async def test_probe_httpbin_returns_verdict():
    """Probe httpbin.org and verify we get a valid assessment back."""
    from apisniff.probe import run_probes

    assessment = await run_probes(
        "https://httpbin.org/get",
        skip_graphql=True,
    )

    assert isinstance(assessment, ProbeAssessment)
    assert assessment.verdict in list(ProbeVerdict)
    assert assessment.url == "https://httpbin.org/get"
    assert "naked" in assessment.results
    assert "impersonated" in assessment.results
    assert "tls_only" in assessment.results


@live
@pytest.mark.asyncio
async def test_probe_returns_probe_results_with_status():
    """Each probe result should have a status code (not None / error)."""
    from apisniff.probe import run_probes

    assessment = await run_probes(
        "https://httpbin.org/get",
        skip_graphql=True,
    )

    for label, result in assessment.results.items():
        # At minimum, we should get a status back (network works)
        assert result.status is not None, (
            f"Probe '{label}' returned None status — possible connectivity issue"
        )
        assert result.error is None, (
            f"Probe '{label}' errored: {result.error}"
        )

"""Hermetic replay tests — monkeypatched HTTP client, no network access."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apisniff.models import CapturedFlow
from apisniff.replay import replay_endpoint, run_replay

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flow(
    method: str = "GET",
    host: str = "localhost",
    path: str = "/api/test",
    response_status: int = 200,
    response_body: bytes = b'{"id": 1, "name": "test"}',
    request_headers: dict | None = None,
    timestamp: float = 1000.0,
) -> CapturedFlow:
    return CapturedFlow(
        method=method,
        host=host,
        path=path,
        url=f"https://{host}{path}",
        request_headers=request_headers or {},
        request_body=b"",
        response_status=response_status,
        response_headers={"content-type": "application/json"},
        response_body=response_body,
        timestamp=timestamp,
    )


def _mock_response(status: int, body: bytes = b"") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    return resp


def _make_session(status: int, body: bytes = b'{"id": 1}'):
    mock_resp = _mock_response(status, body)
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.request = AsyncMock(return_value=mock_resp)
    return session


def _write_bundle(tmp_path: Path, flows: list[CapturedFlow]) -> Path:
    p = tmp_path / "flows.jsonl"
    with open(p, "w") as f:
        for flow in flows:
            f.write(flow.to_jsonl() + "\n")
    return tmp_path


# ---------------------------------------------------------------------------
# replay_endpoint: drift detection
# ---------------------------------------------------------------------------

class TestReplayHermeticDrift:
    """Server returns different status or body shape → 'drift' category."""

    def test_status_mismatch_is_drift(self):
        flow = _flow(response_status=200)
        session = _make_session(201, b'{"id": 1, "name": "test"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "drift"
        assert result.status_match is False

    def test_body_shape_drift_extra_key(self):
        flow = _flow(
            response_status=200,
            response_body=b'{"id": 1}',
        )
        session = _make_session(200, b'{"id": 2, "bonus": "field"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "drift"
        assert result.body_shape_match is False

    def test_body_shape_drift_type_change(self):
        flow = _flow(
            response_status=200,
            response_body=b'{"count": 42}',
        )
        session = _make_session(200, b'{"count": "forty-two"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "drift"
        assert result.body_shape_match is False


# ---------------------------------------------------------------------------
# replay_endpoint: blocked / auth_expired
# ---------------------------------------------------------------------------

class TestReplayHermeticBlocked:
    """Blocked and auth_expired category assignment."""

    def test_429_without_auth_is_blocked(self):
        flow = _flow(response_status=200, request_headers={})
        session = _make_session(429, b"Rate limited")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "blocked"
        assert result.replayed_status == 429

    def test_401_with_auth_is_auth_expired(self):
        flow = _flow(
            response_status=200,
            request_headers={"Authorization": "Bearer tok123"},
        )
        session = _make_session(401, b"Unauthorized")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "auth_expired"


# ---------------------------------------------------------------------------
# run_replay: filter pipeline, abort, dedup
# ---------------------------------------------------------------------------

class TestReplayFilter:
    """run_replay with filter_ only replays matching paths."""

    @pytest.mark.asyncio
    async def test_filter_only_replays_matching_paths(self, tmp_path: Path):
        flows = [
            _flow(path="/api/users", timestamp=1.0),
            _flow(path="/api/posts", timestamp=2.0),
            _flow(path="/api/users/123", timestamp=3.0),
        ]
        bundle = _write_bundle(tmp_path, flows)

        session = _make_session(200, b'{"id": 1, "name": "ok"}')

        with (
            patch("curl_cffi.requests.AsyncSession", return_value=session),
            patch("apisniff.output.render_replay"),
        ):
            results = await run_replay(
                bundle_dir=str(bundle),
                filter_="/api/users*",
            )

        # Only /api/users and /api/users/123 should be replayed
        paths = [r.original_flow.path for r in results]
        assert "/api/posts" not in paths
        assert any("/api/users" in p for p in paths)


class TestRunReplayPipeline:
    """Full run_replay pipeline with monkeypatched HTTP."""

    @pytest.mark.asyncio
    async def test_abort_on_blocked(self, tmp_path: Path):
        """run_replay aborts when blocked, skipping remaining flows."""
        flows = [
            _flow(path="/api/a", timestamp=1.0),
            _flow(path="/api/b", timestamp=2.0),
            _flow(path="/api/c", timestamp=3.0),
        ]
        bundle = _write_bundle(tmp_path, flows)

        session = _make_session(403, b"Forbidden")

        with (
            patch("curl_cffi.requests.AsyncSession", return_value=session),
            patch("apisniff.output.render_replay"),
        ):
            results = await run_replay(bundle_dir=str(bundle))

        # Should abort after first blocked result
        assert len(results) == 1
        assert results[0].category == "blocked"

    @pytest.mark.asyncio
    async def test_deduplication_keeps_latest(self, tmp_path: Path):
        """When same path appears twice, only the most recent is replayed."""
        flows = [
            _flow(
                path="/api/items",
                response_body=b'{"old": true}',
                timestamp=1.0,
            ),
            _flow(
                path="/api/items",
                response_body=b'{"new": true}',
                timestamp=2.0,
            ),
        ]
        bundle = _write_bundle(tmp_path, flows)

        session = _make_session(200, b'{"new": true}')

        with (
            patch("curl_cffi.requests.AsyncSession", return_value=session),
            patch("apisniff.output.render_replay"),
        ):
            results = await run_replay(bundle_dir=str(bundle))

        assert len(results) == 1


# ---------------------------------------------------------------------------
# run_replay: JSON output mode
# ---------------------------------------------------------------------------

class TestRunReplayJsonOutput:
    @pytest.mark.asyncio
    async def test_json_output_to_file(self, tmp_path: Path):
        flows = [_flow(path="/api/x", timestamp=1.0)]
        bundle = _write_bundle(tmp_path, flows)
        output_path = str(tmp_path / "output.json")

        session = _make_session(200, b'{"id": 1, "name": "test"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            await run_replay(
                bundle_dir=str(bundle),
                json_output=True,
                output_file=output_path,
            )

        data = json.loads(Path(output_path).read_text())
        assert data["schema_version"] == 1
        assert "endpoints" in data

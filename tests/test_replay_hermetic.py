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
# replay_endpoint: category assignment against controlled responses
# ---------------------------------------------------------------------------

class TestReplayHermeticMatch:
    """Server returns matching response → 'match' category."""

    def test_same_status_same_shape_is_match(self):
        flow = _flow(
            response_status=200,
            response_body=b'{"id": 1, "name": "alice"}',
        )
        session = _make_session(200, b'{"id": 2, "name": "bob"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "match"
        assert result.status_match is True
        assert result.body_shape_match is True
        assert result.body_shape_diff is None
        assert result.error is None

    def test_both_non_json_is_match(self):
        flow = _flow(
            response_status=200,
            response_body=b"plain text original",
        )
        session = _make_session(200, b"plain text different")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "match"
        assert result.body_shape_match is True


class TestReplayHermeticDrift:
    """Server returns different status or body shape → 'drift' category."""

    def test_status_mismatch_is_drift(self):
        flow = _flow(response_status=200)
        session = _make_session(201, b'{"id": 1, "name": "test"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "drift"
        assert result.status_match is False

    def test_body_shape_drift_missing_key(self):
        flow = _flow(
            response_status=200,
            response_body=b'{"id": 1, "name": "alice", "email": "a@b.com"}',
        )
        # Response drops the "email" key
        session = _make_session(200, b'{"id": 2, "name": "bob"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "drift"
        assert result.status_match is True
        assert result.body_shape_match is False
        assert result.body_shape_diff is not None
        assert "email" in str(result.body_shape_diff)

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

    def test_json_to_non_json_is_drift(self):
        flow = _flow(
            response_status=200,
            response_body=b'{"key": "value"}',
        )
        session = _make_session(200, b"not json at all")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "drift"
        assert result.body_shape_match is False


class TestReplayHermeticBlocked:
    """Server returns 403 without auth headers → 'blocked' category."""

    def test_403_without_auth_is_blocked(self):
        flow = _flow(response_status=200, request_headers={})
        session = _make_session(403, b"Forbidden")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "blocked"
        assert result.replayed_status == 403

    def test_429_without_auth_is_blocked(self):
        flow = _flow(response_status=200, request_headers={})
        session = _make_session(429, b"Rate limited")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "blocked"
        assert result.replayed_status == 429

    def test_503_without_auth_is_blocked(self):
        flow = _flow(response_status=200, request_headers={})
        session = _make_session(503, b"Service Unavailable")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "blocked"

    def test_403_with_auth_is_auth_expired(self):
        flow = _flow(
            response_status=200,
            request_headers={"authorization": "Bearer tok123"},
        )
        session = _make_session(403, b"Forbidden")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "auth_expired"

    def test_401_with_auth_is_auth_expired(self):
        flow = _flow(
            response_status=200,
            request_headers={"Authorization": "Bearer tok123"},
        )
        session = _make_session(401, b"Unauthorized")

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "auth_expired"


class TestReplayHermeticError:
    """Server connection fails → 'error' category."""

    def test_connection_error_is_error(self):
        flow = _flow()
        session = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        session.request = AsyncMock(
            side_effect=ConnectionError("Connection refused")
        )

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "error"
        assert result.error is not None
        assert "Connection refused" in result.error
        assert result.replayed_status is None

    def test_timeout_error_is_error(self):
        flow = _flow()
        session = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        session.request = AsyncMock(
            side_effect=TimeoutError("Request timed out")
        )

        with patch("curl_cffi.requests.AsyncSession", return_value=session):
            result = asyncio.run(replay_endpoint(flow))

        assert result.category == "error"
        assert result.error is not None
        assert result.replayed_status is None


# ---------------------------------------------------------------------------
# run_replay with --filter: only matching paths replayed
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

    @pytest.mark.asyncio
    async def test_filter_no_match_returns_empty(self, tmp_path: Path):
        flows = [
            _flow(path="/api/users", timestamp=1.0),
        ]
        bundle = _write_bundle(tmp_path, flows)

        with patch("apisniff.output.render_replay"):
            results = await run_replay(
                bundle_dir=str(bundle),
                filter_="/api/nonexistent*",
            )

        assert results == []


# ---------------------------------------------------------------------------
# run_replay: end-to-end through the pipeline
# ---------------------------------------------------------------------------

class TestRunReplayPipeline:
    """Full run_replay pipeline with monkeypatched HTTP."""

    @pytest.mark.asyncio
    async def test_multiple_flows_all_match(self, tmp_path: Path):
        flows = [
            _flow(
                path="/api/a",
                response_body=b'{"a": 1}',
                timestamp=1.0,
            ),
            _flow(
                path="/api/b",
                response_body=b'{"b": 2}',
                timestamp=2.0,
            ),
        ]
        bundle = _write_bundle(tmp_path, flows)

        call_bodies = {
            "https://localhost/api/a": b'{"a": 99}',
            "https://localhost/api/b": b'{"b": 99}',
        }

        session = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)

        async def fake_request(**kwargs):
            url = kwargs["url"]
            body = call_bodies.get(url, b'{}')
            return _mock_response(200, body)

        session.request = fake_request

        with (
            patch("curl_cffi.requests.AsyncSession", return_value=session),
            patch("apisniff.output.render_replay"),
        ):
            results = await run_replay(bundle_dir=str(bundle))

        assert len(results) == 2
        assert all(r.category == "match" for r in results)

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

    @pytest.mark.asyncio
    async def test_unsafe_methods_excluded_by_default(self, tmp_path: Path):
        """POST/PUT/DELETE excluded unless include_unsafe=True."""
        flows = [
            _flow(method="GET", path="/api/safe", timestamp=1.0),
            _flow(method="POST", path="/api/unsafe", timestamp=2.0),
            _flow(method="DELETE", path="/api/also-unsafe", timestamp=3.0),
        ]
        bundle = _write_bundle(tmp_path, flows)

        session = _make_session(200, b'{"id": 1, "name": "test"}')

        with (
            patch("curl_cffi.requests.AsyncSession", return_value=session),
            patch("apisniff.output.render_replay"),
        ):
            results = await run_replay(bundle_dir=str(bundle))

        assert len(results) == 1
        assert results[0].original_flow.method == "GET"

    @pytest.mark.asyncio
    async def test_include_unsafe_replays_all(self, tmp_path: Path):
        """With include_unsafe, POST/DELETE are replayed."""
        flows = [
            _flow(method="GET", path="/api/safe", timestamp=1.0),
            _flow(method="POST", path="/api/create", timestamp=2.0),
        ]
        bundle = _write_bundle(tmp_path, flows)

        session = _make_session(200, b'{"id": 1, "name": "test"}')

        with (
            patch("curl_cffi.requests.AsyncSession", return_value=session),
            patch("apisniff.output.render_replay"),
        ):
            results = await run_replay(
                bundle_dir=str(bundle),
                include_unsafe=True,
            )

        methods = [r.original_flow.method for r in results]
        assert "GET" in methods
        assert "POST" in methods


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

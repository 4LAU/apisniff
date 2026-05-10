from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from apisniff.models import CapturedFlow
from apisniff.replay import (
    compare_shape,
    cookies_for_host,
    parse_cookie_file,
    replay_endpoint,
    run_replay,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flow(
    method: str = "GET",
    path: str = "/api/test",
    response_status: int = 200,
    response_body: bytes = b'{"id": 1, "name": "test"}',
    request_headers: dict | None = None,
    timestamp: float = 1000.0,
) -> CapturedFlow:
    return CapturedFlow(
        method=method,
        host="api.example.com",
        path=path,
        url=f"https://api.example.com{path}",
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


# ---------------------------------------------------------------------------
# 7a. compare_shape
# ---------------------------------------------------------------------------

class TestCompareShape:
    def test_matching_json(self):
        a = b'{"id": 1, "name": "alice"}'
        b_ = b'{"id": 2, "name": "bob"}'
        match, diff = compare_shape(a, b_)
        assert match is True
        assert diff is None

    def test_added_key_is_drift(self):
        a = b'{"id": 1}'
        b_ = b'{"id": 2, "extra": "field"}'
        match, diff = compare_shape(a, b_)
        assert match is False
        assert diff is not None
        assert "extra" in str(diff)

    def test_removed_key_is_drift(self):
        a = b'{"id": 1, "name": "test"}'
        b_ = b'{"id": 2}'
        match, diff = compare_shape(a, b_)
        assert match is False
        assert diff is not None
        assert "name" in str(diff)

    def test_type_change_is_drift(self):
        # id changes from int to str
        a = b'{"id": 1}'
        b_ = b'{"id": "abc"}'
        match, diff = compare_shape(a, b_)
        assert match is False
        assert diff is not None

    def test_primitive_array_same_type_matches(self):
        a = b'{"ids": [1, 2, 3]}'
        b_ = b'{"ids": [4, 5, 6]}'
        match, diff = compare_shape(a, b_)
        assert match is True
        assert diff is None

    def test_primitive_array_type_change_is_drift(self):
        a = b'{"ids": [1, 2, 3]}'
        b_ = b'{"ids": ["a", "b", "c"]}'
        match, diff = compare_shape(a, b_)
        assert match is False
        assert diff is not None

    def test_json_vs_non_json_is_drift(self):
        a = b'{"key": "value"}'
        b_ = b"plain text response"
        match, diff = compare_shape(a, b_)
        assert match is False
        assert diff is not None
        assert "json_parse_mismatch" in diff

    def test_non_json_vs_json_is_drift(self):
        a = b"plain text response"
        b_ = b'{"key": "value"}'
        match, diff = compare_shape(a, b_)
        assert match is False
        assert diff is not None

    def test_both_non_json_matches(self):
        a = b"plain text"
        b_ = b"different plain text"
        match, diff = compare_shape(a, b_)
        assert match is True
        assert diff is None

    def test_nested_shape_drift(self):
        a = b'{"user": {"id": 1, "role": "admin"}}'
        b_ = b'{"user": {"id": 2}}'
        match, diff = compare_shape(a, b_)
        assert match is False
        assert diff is not None

    def test_empty_bodies_match(self):
        match, diff = compare_shape(b"", b"")
        assert match is True
        assert diff is None


# ---------------------------------------------------------------------------
# 7b. Cookie parsing
# ---------------------------------------------------------------------------

NETSCAPE_COOKIES = """\
# Netscape HTTP Cookie File
.example.com\tTRUE\t/\tFALSE\t0\tsession\tabc123
api.example.com\tFALSE\t/\tFALSE\t0\tcsrf\txyz789
.other.com\tTRUE\t/\tFALSE\t0\tsecret\t999
"""


class TestCookieParsing:
    def _write_cookies(self, tmp_path: Path, content: str) -> str:
        p = tmp_path / "cookies.txt"
        p.write_text(content)
        return str(p)

    def test_parse_returns_tuples(self, tmp_path: Path):
        path = self._write_cookies(tmp_path, NETSCAPE_COOKIES)
        result = parse_cookie_file(path)
        assert len(result) == 3
        assert result[0] == (".example.com", "session", "abc123")
        assert result[1] == ("api.example.com", "csrf", "xyz789")
        assert result[2] == (".other.com", "secret", "999")

    def test_suffix_match_applies_to_subdomain(self, tmp_path: Path):
        cookies = parse_cookie_file(self._write_cookies(tmp_path, NETSCAPE_COOKIES))
        header = cookies_for_host(cookies, "api.example.com")
        assert "session=abc123" in header
        assert "csrf=xyz789" in header
        assert "secret=999" not in header

    def test_other_com_not_matched(self, tmp_path: Path):
        cookies = parse_cookie_file(self._write_cookies(tmp_path, NETSCAPE_COOKIES))
        header = cookies_for_host(cookies, "api.example.com")
        assert "999" not in header

    def test_exact_domain_match(self):
        cookies = [("api.example.com", "token", "abc")]
        header = cookies_for_host(cookies, "api.example.com")
        assert header == "token=abc"

    def test_exact_domain_no_subdomain_bleed(self):
        cookies = [("example.com", "token", "abc")]
        header = cookies_for_host(cookies, "other.com")
        assert header == ""

    def test_suffix_match_apex_too(self):
        cookies = [(".example.com", "session", "xyz")]
        header = cookies_for_host(cookies, "example.com")
        assert "session=xyz" in header

    def test_no_match_returns_empty_string(self, tmp_path: Path):
        cookies = parse_cookie_file(self._write_cookies(tmp_path, NETSCAPE_COOKIES))
        header = cookies_for_host(cookies, "unrelated.io")
        assert header == ""


# ---------------------------------------------------------------------------
# 7c. replay_endpoint — category assignment
# ---------------------------------------------------------------------------

class TestReplayEndpoint:
    def _make_session_mock(self, status: int, body: bytes = b'{"id": 1}'):
        mock_resp = _mock_response(status, body)
        session_mock = AsyncMock()
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__ = AsyncMock(return_value=False)
        session_mock.request = AsyncMock(return_value=mock_resp)
        return session_mock

    def _run(self, coro):
        return asyncio.run(coro)

    def test_200_to_200_same_shape_is_match(self):
        flow = _flow(
            response_status=200,
            response_body=b'{"id": 1, "name": "test"}',
        )
        session_mock = self._make_session_mock(200, b'{"id": 2, "name": "other"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            result = self._run(replay_endpoint(flow))

        assert result.category == "match"
        assert result.status_match is True

    def test_200_to_403_with_auth_is_auth_expired(self):
        flow = _flow(
            response_status=200,
            request_headers={"authorization": "Bearer token123"},
        )
        session_mock = self._make_session_mock(403, b"Forbidden")

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            result = self._run(replay_endpoint(flow))

        assert result.category == "auth_expired"

    def test_200_to_403_without_auth_is_blocked(self):
        flow = _flow(
            response_status=200,
            request_headers={},
        )
        session_mock = self._make_session_mock(403, b"Forbidden")

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            result = self._run(replay_endpoint(flow))

        assert result.category == "blocked"

    def test_200_to_200_shape_drift_is_drift(self):
        flow = _flow(
            response_status=200,
            response_body=b'{"id": 1, "name": "test", "role": "admin"}',
        )
        # Response drops the "role" key
        session_mock = self._make_session_mock(200, b'{"id": 2, "name": "bob"}')

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            result = self._run(replay_endpoint(flow))

        assert result.category == "drift"
        assert result.status_match is True
        assert result.body_shape_match is False

    def test_connection_error_is_error(self):
        flow = _flow()
        session_mock = AsyncMock()
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__ = AsyncMock(return_value=False)
        session_mock.request = AsyncMock(
            side_effect=ConnectionError("Connection refused")
        )

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            result = self._run(replay_endpoint(flow))

        assert result.category == "error"
        assert result.error is not None
        assert result.replayed_status is None

    def test_size_delta_over_50pct_is_drift(self):
        orig_body = b'{"data": "' + b"x" * 200 + b'"}'
        flow = _flow(
            response_status=200,
            response_body=orig_body,
        )
        # Reply with tiny body — same shape but <50% size
        small_body = b'{"data": "x"}'
        session_mock = self._make_session_mock(200, small_body)

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            result = self._run(replay_endpoint(flow))

        assert result.category == "drift"


# ---------------------------------------------------------------------------
# 7d. run_replay — method safety filter
# ---------------------------------------------------------------------------

class TestMethodFilter:
    """Verify safety filter logic without running real HTTP."""

    def _make_bundle(self, flows: list[CapturedFlow]) -> tempfile.TemporaryDirectory:
        """Return a TemporaryDirectory whose path contains a flows.jsonl."""
        tmpdir = tempfile.TemporaryDirectory()
        p = Path(tmpdir.name) / "flows.jsonl"
        with open(p, "w") as f:
            for flow in flows:
                f.write(flow.to_jsonl() + "\n")
        return tmpdir

    def _run_dry(
        self, tmpdir: tempfile.TemporaryDirectory, include_unsafe: bool = False
    ) -> list[str]:
        """Run replay in dry_run mode and return the methods of surviving flows."""
        from apisniff import replay as replay_mod

        captured: list[CapturedFlow] = []
        original_filter = replay_mod._filter_flows

        def capturing_filter(flows, include_unsafe_):
            safe, unsafe = original_filter(flows, include_unsafe_)
            captured.extend(safe)
            return safe, unsafe

        with patch.object(replay_mod, "_filter_flows", side_effect=capturing_filter):
            with patch("apisniff.output.render_dry_run"):
                asyncio.run(
                    run_replay(
                        bundle_dir=tmpdir.name,
                        include_unsafe=include_unsafe,
                        dry_run=True,
                    )
                )
        return [f.method for f in captured]

    def test_get_included_by_default(self):
        tmpdir = self._make_bundle([_flow("GET"), _flow("POST")])
        with tmpdir:
            methods = self._run_dry(tmpdir, include_unsafe=False)
        assert "GET" in methods
        assert "POST" not in methods

    def test_post_excluded_by_default(self):
        tmpdir = self._make_bundle([_flow("POST")])
        with tmpdir:
            methods = self._run_dry(tmpdir, include_unsafe=False)
        assert methods == []

    def test_post_included_with_include_unsafe(self):
        tmpdir = self._make_bundle([_flow("GET"), _flow("POST")])
        with tmpdir:
            methods = self._run_dry(tmpdir, include_unsafe=True)
        assert "GET" in methods
        assert "POST" in methods

    def test_head_and_options_included_by_default(self):
        tmpdir = self._make_bundle([_flow("HEAD"), _flow("OPTIONS")])
        with tmpdir:
            methods = self._run_dry(tmpdir, include_unsafe=False)
        assert "HEAD" in methods
        assert "OPTIONS" in methods


class TestEarlyAbort:
    """Replay aborts on auth failure instead of continuing."""

    def _make_bundle(self, tmp_path: Path, flows: list[CapturedFlow]) -> Path:
        p = tmp_path / "flows.jsonl"
        with open(p, "w") as f:
            for flow in flows:
                f.write(flow.to_jsonl() + "\n")
        return tmp_path

    def test_aborts_on_auth_expired(self, tmp_path: Path):
        flows = [
            _flow(
                path="/api/a",
                request_headers={"authorization": "Bearer tok"},
                timestamp=1.0,
            ),
            _flow(path="/api/b", timestamp=2.0),
            _flow(path="/api/c", timestamp=3.0),
        ]
        bundle = self._make_bundle(tmp_path, flows)

        session_mock = AsyncMock()
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__ = AsyncMock(return_value=False)
        session_mock.request = AsyncMock(
            return_value=_mock_response(403, b"Forbidden")
        )

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            with patch("apisniff.output.render_replay"):
                results = asyncio.run(
                    run_replay(bundle_dir=str(bundle))
                )

        assert len(results) == 1
        assert results[0].category == "auth_expired"

    def test_aborts_on_blocked(self, tmp_path: Path):
        flows = [
            _flow(path="/api/a", timestamp=1.0),
            _flow(path="/api/b", timestamp=2.0),
        ]
        bundle = self._make_bundle(tmp_path, flows)

        session_mock = AsyncMock()
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__ = AsyncMock(return_value=False)
        session_mock.request = AsyncMock(
            return_value=_mock_response(403, b"Forbidden")
        )

        with patch("curl_cffi.requests.AsyncSession", return_value=session_mock):
            with patch("apisniff.output.render_replay"):
                results = asyncio.run(
                    run_replay(bundle_dir=str(bundle))
                )

        assert len(results) == 1
        assert results[0].category == "blocked"

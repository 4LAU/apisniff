"""Format-parity invariants: same logical traffic, three containers.

Without these tests, a parser change could silently drop or corrupt flows
in one format while the others remain correct.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apisniff.adapters.burp import burp_to_flows
from apisniff.adapters.har import har_to_flows
from apisniff.bundle import read_capture_jsonl

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _flow_identity(flows):
    return [(f.method, f.host, f.path, f.response_status) for f in flows]


class TestFormatParity:
    """minimal.har, minimal.burp.xml, and minimal.jsonl represent
    the same 5 flows. One invariant, three formats."""

    @pytest.fixture()
    def har_flows(self):
        return har_to_flows((FIXTURES_DIR / "minimal.har").read_text())

    @pytest.fixture()
    def burp_flows(self):
        return burp_to_flows((FIXTURES_DIR / "minimal.burp.xml").read_text())

    @pytest.fixture()
    def jsonl_flows(self):
        return read_capture_jsonl(str(FIXTURES_DIR / "minimal.jsonl"))

    def test_same_flow_count(self, har_flows, burp_flows, jsonl_flows):
        assert len(har_flows) == len(burp_flows) == len(jsonl_flows) == 5

    def test_same_methods(self, har_flows, burp_flows, jsonl_flows):
        methods = [f.method for f in har_flows]
        assert methods == [f.method for f in burp_flows]
        assert methods == [f.method for f in jsonl_flows]
        assert methods == ["GET", "POST", "GET", "POST", "POST"]

    def test_same_hosts(self, har_flows, burp_flows, jsonl_flows):
        hosts = [f.host for f in har_flows]
        assert hosts == [f.host for f in burp_flows]
        assert hosts == [f.host for f in jsonl_flows]
        assert all(h == "example.com" for h in hosts)

    def test_same_paths(self, har_flows, burp_flows, jsonl_flows):
        paths = [f.path for f in har_flows]
        assert paths == [f.path for f in burp_flows]
        assert paths == [f.path for f in jsonl_flows]
        assert paths == [
            "/api/users",
            "/api/users",
            "/style.css",
            "/analytics/track",
            "/auth/login",
        ]

    def test_same_status_codes(self, har_flows, burp_flows, jsonl_flows):
        statuses = [f.response_status for f in har_flows]
        assert statuses == [f.response_status for f in burp_flows]
        assert statuses == [f.response_status for f in jsonl_flows]
        assert statuses == [200, 201, 200, 204, 200]

    def test_same_content_types(self, har_flows, burp_flows, jsonl_flows):
        har_cts = [f.content_type for f in har_flows]
        assert har_cts == [f.content_type for f in burp_flows]
        assert har_cts == [f.content_type for f in jsonl_flows]

    def test_same_response_bodies(self, har_flows, burp_flows, jsonl_flows):
        for h, b, j in zip(har_flows, burp_flows, jsonl_flows, strict=True):
            assert h.response_body == b.response_body == j.response_body

    def test_same_request_bodies(self, har_flows, burp_flows, jsonl_flows):
        for h, b, j in zip(har_flows, burp_flows, jsonl_flows, strict=True):
            assert h.request_body == b.request_body == j.request_body

    def test_identity_tuples_match(self, har_flows, burp_flows, jsonl_flows):
        assert _flow_identity(har_flows) == _flow_identity(burp_flows)
        assert _flow_identity(har_flows) == _flow_identity(jsonl_flows)

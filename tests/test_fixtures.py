"""Tests validating the fixture corpus and format-parity invariants."""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree.ElementTree import ParseError

import pytest

from apisniff.adapters.burp import burp_to_flows
from apisniff.adapters.har import har_to_flows
from apisniff.bundle import detect_input_format, read_capture_jsonl

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flow_identity(flows):
    """Extract (method, host, path, status) tuples for comparison."""
    return [(f.method, f.host, f.path, f.response_status) for f in flows]


def _flow_content_types(flows):
    """Extract response content types for comparison."""
    return [f.content_type for f in flows]


# ---------------------------------------------------------------------------
# Fixture loading — each file parses without error
# ---------------------------------------------------------------------------

class TestFixtureLoading:
    """Every fixture file loads through its parser without error."""

    def test_minimal_har_loads(self):
        flows = har_to_flows((FIXTURES_DIR / "minimal.har").read_text())
        assert len(flows) == 5

    def test_minimal_burp_loads(self):
        flows = burp_to_flows((FIXTURES_DIR / "minimal.burp.xml").read_text())
        assert len(flows) == 5

    def test_minimal_jsonl_loads(self):
        flows = read_capture_jsonl(str(FIXTURES_DIR / "minimal.jsonl"))
        assert len(flows) == 5

    def test_multisite_har_loads(self):
        flows = har_to_flows((FIXTURES_DIR / "multisite.har").read_text())
        assert len(flows) == 8

    def test_auth_variants_har_loads(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        assert len(flows) == 6

    def test_redaction_jsonl_loads(self):
        flows = read_capture_jsonl(str(FIXTURES_DIR / "redaction.jsonl"))
        assert len(flows) == 5

    def test_empty_har_loads(self):
        flows = har_to_flows((FIXTURES_DIR / "empty.har").read_text())
        assert len(flows) == 0


# ---------------------------------------------------------------------------
# Format parity — same logical traffic, three containers
# ---------------------------------------------------------------------------

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
        cts = _flow_content_types(har_flows)
        assert cts == _flow_content_types(burp_flows)
        assert cts == _flow_content_types(jsonl_flows)
        assert cts == [
            "application/json",
            "application/json",
            "text/css",
            "application/json",
            "application/json",
        ]

    def test_same_response_bodies(self, har_flows, burp_flows, jsonl_flows):
        for h, b, j in zip(har_flows, burp_flows, jsonl_flows, strict=True):
            assert h.response_body == b.response_body == j.response_body

    def test_same_request_bodies(self, har_flows, burp_flows, jsonl_flows):
        for h, b, j in zip(har_flows, burp_flows, jsonl_flows, strict=True):
            assert h.request_body == b.request_body == j.request_body

    def test_identity_tuples_match(self, har_flows, burp_flows, jsonl_flows):
        assert _flow_identity(har_flows) == _flow_identity(burp_flows)
        assert _flow_identity(har_flows) == _flow_identity(jsonl_flows)


# ---------------------------------------------------------------------------
# Multisite fixture — host diversity
# ---------------------------------------------------------------------------

class TestMultisiteFixture:

    def test_eight_flows_across_three_hosts(self):
        flows = har_to_flows((FIXTURES_DIR / "multisite.har").read_text())
        assert len(flows) == 8
        hosts = {f.host for f in flows}
        assert hosts == {"example.com", "api.example.com", "api.stripe.com"}

    def test_host_distribution(self):
        flows = har_to_flows((FIXTURES_DIR / "multisite.har").read_text())
        by_host: dict[str, int] = {}
        for f in flows:
            by_host[f.host] = by_host.get(f.host, 0) + 1
        assert by_host["example.com"] == 3
        assert by_host["api.example.com"] == 3
        assert by_host["api.stripe.com"] == 2


# ---------------------------------------------------------------------------
# Auth variants fixture
# ---------------------------------------------------------------------------

class TestAuthVariantsFixture:

    def test_six_flows(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        assert len(flows) == 6

    def test_bearer_token_present(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        bearer_flows = [
            f for f in flows
            if f.request_headers.get("authorization", "").startswith("Bearer ")
        ]
        assert len(bearer_flows) >= 1

    def test_basic_auth_present(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        basic_flows = [
            f for f in flows
            if f.request_headers.get("authorization", "").startswith("Basic ")
        ]
        assert len(basic_flows) >= 1

    def test_api_key_header_present(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        api_key_flows = [
            f for f in flows
            if "x-api-key" in f.request_headers
        ]
        assert len(api_key_flows) >= 1

    def test_api_key_query_param_present(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        api_key_query_flows = [
            f for f in flows if "api_key=" in f.path
        ]
        assert len(api_key_query_flows) >= 1

    def test_session_cookie_present(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        cookie_flows = [
            f for f in flows if "session=" in f.request_headers.get("cookie", "")
        ]
        assert len(cookie_flows) >= 1

    def test_oauth_token_endpoint_present(self):
        flows = har_to_flows((FIXTURES_DIR / "auth_variants.har").read_text())
        token_flows = [
            f for f in flows if f.path.startswith("/oauth/token")
        ]
        assert len(token_flows) >= 1


# ---------------------------------------------------------------------------
# Redaction fixture — secret patterns present
# ---------------------------------------------------------------------------

class TestRedactionFixture:

    @pytest.fixture()
    def flows(self):
        return read_capture_jsonl(str(FIXTURES_DIR / "redaction.jsonl"))

    def test_five_flows_loaded(self, flows):
        assert len(flows) == 5

    def test_bearer_token_in_header(self, flows):
        assert any(
            "Bearer " in f.request_headers.get("authorization", "")
            for f in flows
        )

    def test_sk_live_in_request_body(self, flows):
        assert any(
            b"sk_live_" in f.request_body
            for f in flows
        )

    def test_password_field_in_request_body(self, flows):
        assert any(
            b'"password"' in f.request_body
            for f in flows
        )

    def test_api_key_in_query_params(self, flows):
        assert any("api_key=" in f.path for f in flows)


# ---------------------------------------------------------------------------
# Error handling — malformed inputs
# ---------------------------------------------------------------------------

class TestMalformedInputs:

    def test_malformed_har_raises_json_decode_error(self):
        text = (FIXTURES_DIR / "malformed.har").read_text()
        with pytest.raises(json.JSONDecodeError):
            har_to_flows(text)

    def test_malformed_xml_raises_parse_error(self):
        text = (FIXTURES_DIR / "malformed.xml").read_text()
        with pytest.raises(ParseError):
            burp_to_flows(text)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

class TestFormatDetection:

    @pytest.mark.parametrize(
        "filename, expected_format",
        [
            ("minimal.har", "har"),
            ("minimal.burp.xml", "burp"),
            ("minimal.jsonl", "jsonl"),
            ("multisite.har", "har"),
            ("auth_variants.har", "har"),
            ("empty.har", "har"),
            ("malformed.har", "har"),
            ("malformed.xml", "burp"),
            ("redaction.jsonl", "jsonl"),
        ],
    )
    def test_detect_input_format(self, filename, expected_format):
        head = (FIXTURES_DIR / filename).read_text()[:1024]
        assert detect_input_format(head) == expected_format

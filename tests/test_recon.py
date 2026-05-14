import tempfile
from pathlib import Path

import pytest

from apisniff.models import CapturedFlow
from apisniff.recon import (
    _normalize_target,
    detect_input_format,
    read_capture_jsonl,
    write_flow_jsonl,
)


def test_write_and_read_jsonl():
    flow = CapturedFlow(
        method="GET",
        host="example.com",
        path="/api/users",
        url="https://example.com/api/users",
        request_headers={"user-agent": "Chrome"},
        request_body=b"",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"users": []}',
        tags=["api_signal"],
        timestamp=1715100000.0,
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = f.name
        write_flow_jsonl(f, flow)

    try:
        flows = read_capture_jsonl(path)
        assert len(flows) == 1
        assert flows[0].method == "GET"
        assert flows[0].host == "example.com"
        assert flows[0].tags == ["api_signal"]
    finally:
        Path(path).unlink()


def test_read_jsonl_skips_malformed_lines(tmp_path: Path):
    valid_line = CapturedFlow(
        method="GET",
        host="example.com",
        path="/ok",
        url="https://example.com/ok",
        request_headers={},
        request_body=b"",
        response_status=200,
        response_headers={},
        response_body=b"{}",
        tags=[],
        timestamp=1715100000.0,
    ).to_jsonl()

    p = tmp_path / "mixed.jsonl"
    p.write_text("\n".join([
        valid_line,
        "not json at all",
        '{"method": "GET"}',
        "",
        valid_line,
    ]))

    flows = read_capture_jsonl(str(p))
    assert len(flows) == 2


def test_detect_input_format_har():
    har = '{"log": {"entries": []}}'
    assert detect_input_format(har) == "har"


def test_detect_input_format_jsonl_with_log_field():
    line = '{"method": "GET", "host": "example.com", "log": "debug info"}'
    assert detect_input_format(line) == "jsonl"


def test_detect_input_format_burp():
    burp_head = '<?xml version="1.0"?><items burpVersion="2023.1"><item></item></items>'
    assert detect_input_format(burp_head) == "burp"


def test_detect_input_format_non_burp_xml():
    svg_head = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>'
    assert detect_input_format(svg_head) == "unknown"


@pytest.mark.parametrize("raw, expected_domain, expected_url", [
    ("example.com", "example.com", "https://example.com"),
    ("https://example.com/path", "example.com", "https://example.com/path"),
    ("http://example.com/path", "example.com", "http://example.com/path"),
    ("https://www.t-mobile.com/guest-pay", "www.t-mobile.com", "https://www.t-mobile.com/guest-pay"),
])
def test_normalize_target(raw, expected_domain, expected_url):
    domain, url = _normalize_target(raw)
    assert domain == expected_domain
    assert url == expected_url



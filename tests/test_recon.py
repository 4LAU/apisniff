# tests/test_recon.py
import tempfile
from pathlib import Path

from apisniff.models import CapturedFlow
from apisniff.recon import detect_input_format, read_capture_jsonl, write_flow_jsonl


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

    flows = read_capture_jsonl(path)
    assert len(flows) == 1
    assert flows[0].method == "GET"
    assert flows[0].host == "example.com"
    assert flows[0].tags == ["api_signal"]
    Path(path).unlink()


def test_detect_input_format_har():
    har = '{"log": {"entries": []}}'
    assert detect_input_format(har) == "har"


def test_detect_input_format_jsonl():
    line = '{"method": "GET", "host": "example.com"}'
    assert detect_input_format(line) == "jsonl"

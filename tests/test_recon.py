# tests/test_recon.py
import json
import tempfile
from pathlib import Path

from apisniff.models import CapturedFlow
from apisniff.recon import detect_input_format, load_flows, read_capture_jsonl, write_flow_jsonl


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


def test_detect_input_format_har():
    har = '{"log": {"entries": []}}'
    assert detect_input_format(har) == "har"


def test_detect_input_format_jsonl():
    line = '{"method": "GET", "host": "example.com"}'
    assert detect_input_format(line) == "jsonl"


def test_detect_input_format_burp():
    burp_head = '<?xml version="1.0"?><items burpVersion="2023.1"><item></item></items>'
    assert detect_input_format(burp_head) == "burp"


def test_detect_input_format_non_burp_xml():
    svg_head = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>'
    assert detect_input_format(svg_head) == "unknown"


def test_load_flows_har():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/users",
                        "headers": [{"name": "user-agent", "value": "Chrome"}],
                        "postData": None,
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "content-type", "value": "application/json"}],
                        "content": {"text": '{"users": []}', "mimeType": "application/json"},
                    },
                    "startedDateTime": "2024-01-01T00:00:00Z",
                }
            ]
        }
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".har", delete=False, encoding="utf-8"
    ) as f:
        path = f.name
        json.dump(har, f)
    try:
        flows, fmt = load_flows(path)
        assert fmt == "har"
        assert len(flows) == 1
        assert flows[0].method == "GET"
    finally:
        Path(path).unlink()


def test_load_flows_jsonl():
    flow = CapturedFlow(
        method="POST",
        host="api.example.com",
        path="/v1/items",
        url="https://api.example.com/v1/items",
        request_headers={},
        request_body=b"{}",
        response_status=201,
        response_headers={"content-type": "application/json"},
        response_body=b'{"id": 1}',
        tags=[],
        timestamp=1715100000.0,
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        path = f.name
        write_flow_jsonl(f, flow)
    try:
        flows, fmt = load_flows(path)
        assert fmt == "jsonl"
        assert len(flows) == 1
        assert flows[0].method == "POST"
        assert flows[0].host == "api.example.com"
    finally:
        Path(path).unlink()

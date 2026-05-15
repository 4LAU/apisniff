import json
import signal
import tempfile
from pathlib import Path

import pytest

from apisniff.models import CapturedFlow, SessionStats
from apisniff.recon import (
    _normalize_target,
    detect_input_format,
    read_capture_jsonl,
    run_recon,
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


def test_run_recon_stops_proxy_when_setup_raises(monkeypatch, tmp_path: Path):
    class FakeProc:
        returncode = None

        def __init__(self) -> None:
            self.signals: list[int] = []
            self.killed = False

        def poll(self):
            return self.returncode

        def send_signal(self, sig: int) -> None:
            self.signals.append(sig)

        def wait(self, timeout=None):
            self.returncode = 0
            return self.returncode

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

    proxy_proc = FakeProc()

    def raise_setup_error() -> bool:
        raise RuntimeError("trust check failed")

    popen_args = []

    def fake_popen(*args, **kwargs):
        popen_args.append(args[0])
        return proxy_proc

    monkeypatch.setattr("apisniff.recon.CAPTURES_DIR", tmp_path)
    monkeypatch.setattr("apisniff.recon.time.sleep", lambda _: None)
    monkeypatch.setattr("apisniff.recon._is_ca_trusted", raise_setup_error)
    monkeypatch.setattr("apisniff.recon.subprocess.Popen", fake_popen)

    with pytest.raises(RuntimeError, match="trust check failed"):
        run_recon("example.com")

    assert "--listen-host" in popen_args[0]
    assert popen_args[0][popen_args[0].index("--listen-host") + 1] == "127.0.0.1"
    assert proxy_proc.signals == [signal.SIGINT]
    assert proxy_proc.returncode == 0


def test_run_recon_json_outputs_enriched_capture(monkeypatch, tmp_path: Path, capsys):
    flow = CapturedFlow(
        method="GET",
        host="api.example.com",
        path="/api/users/123",
        url="https://api.example.com/api/users/123",
        request_headers={"authorization": "Bearer token"},
        request_body=b"",
        response_status=200,
        response_headers={
            "content-type": "application/json",
            "cf-mitigated": "challenge",
        },
        response_body=b'{"id":123}',
        tags=["api_signal"],
        timestamp=1715100000.0,
    )

    class FakeProc:
        def __init__(self, env=None) -> None:
            self.returncode = None
            self.output_path = Path(env["APISNIFF_OUTPUT"]) if env else None

        def poll(self):
            return self.returncode

        def send_signal(self, sig: int) -> None:
            self.returncode = 0

        def wait(self, timeout=None):
            if self.output_path is not None:
                self.output_path.write_text(flow.to_jsonl() + "\n")
                session = SessionStats(
                    domain="example.com",
                    started_at="2026-05-14T10:00:00+00:00",
                    duration_seconds=0.0,
                    total_flows=1,
                    kept_flows=1,
                    dropped={},
                )
                (self.output_path.parent / "session.json").write_text(
                    json.dumps(session.to_dict())
                )
            self.returncode = 0
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def kill(self) -> None:
            self.returncode = -9

    def fake_popen(*args, **kwargs):
        return FakeProc(kwargs.get("env"))

    monkeypatch.setattr("apisniff.recon.CAPTURES_DIR", tmp_path)
    monkeypatch.setattr("apisniff.recon.time.sleep", lambda _: None)
    monkeypatch.setattr("apisniff.recon._is_ca_trusted", lambda: True)
    monkeypatch.setattr("apisniff.recon.subprocess.Popen", fake_popen)

    run_recon("example.com", json_output=True)

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert data["schema_version"] == 1
    assert data["domain"] == "example.com"
    assert data["vendors"][0]["vendor"] == "cloudflare"
    assert data["auth_patterns"] == [
        {
            "auth_type": "bearer",
            "detail": "authorization: bearer",
            "flow_count": 1,
        }
    ]
    assert data["top_endpoints"] == [
        {"method": "GET", "path": "/api/users/{id}", "count": 1}
    ]

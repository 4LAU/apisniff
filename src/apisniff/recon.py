# src/apisniff/recon.py
from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import IO

from rich.console import Console

from apisniff.models import CapturedFlow

_CAPTURES_DIR = Path.home() / "apisniff-captures"

console = Console()


def write_flow_jsonl(f: IO, flow: CapturedFlow) -> None:
    record = {
        "method": flow.method,
        "host": flow.host,
        "path": flow.path,
        "url": flow.url,
        "request_headers": flow.request_headers,
        "request_body": flow.request_body.decode("utf-8", errors="replace"),
        "response_status": flow.response_status,
        "response_headers": flow.response_headers,
        "response_body": flow.response_body.decode("utf-8", errors="replace"),
        "tags": flow.tags,
        "timestamp": flow.timestamp,
    }
    f.write(json.dumps(record) + "\n")
    f.flush()


def read_capture_jsonl(path: str) -> list[CapturedFlow]:
    flows: list[CapturedFlow] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            flows.append(CapturedFlow(
                method=d["method"],
                host=d["host"],
                path=d["path"],
                url=d["url"],
                request_headers=d.get("request_headers", {}),
                request_body=d.get("request_body", "").encode("utf-8"),
                response_status=d.get("response_status", 0),
                response_headers=d.get("response_headers", {}),
                response_body=d.get("response_body", "").encode("utf-8"),
                tags=d.get("tags", []),
                timestamp=d.get("timestamp", 0.0),
            ))
    return flows


def detect_input_format(first_bytes: str) -> str:
    stripped = first_bytes.strip()
    if stripped.startswith('{"log"'):
        return "har"
    if stripped.startswith("{") and '"method"' in stripped:
        return "jsonl"
    return "unknown"


def run_recon(
    domain: str,
    port: int = 8080,
    proxy: str | None = None,
    json_output: bool = False,
) -> None:
    _CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    safe_domain = domain.replace(".", "-").replace("/", "-")
    output_path = _CAPTURES_DIR / f"{safe_domain}_{ts}.jsonl"

    addon_path = Path(__file__).parent / "proxy.py"

    cmd = [
        sys.executable, "-m", "mitmproxy",
        "--listen-port", str(port),
        "--set", "console_eventlog_verbosity=error",
        "-s", str(addon_path),
        "--set", f"apisniff_target={domain}",
        "--set", f"apisniff_output={output_path}",
    ]
    if proxy:
        cmd.extend(["--mode", f"upstream:{proxy}"])

    chrome_profile = Path(f"/tmp/apisniff-chrome-{port}")
    chrome_cmd = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        f"--proxy-server=http://127.0.0.1:{port}",
        f"--user-data-dir={chrome_profile}",
        "--no-first-run",
        "--no-default-browser-check",
        f"https://{domain}",
    ]

    console.print(f"\n[bold]apisniff recon[/bold] — {domain}")
    console.print(f"  Proxy: 127.0.0.1:{port}")
    console.print(f"  Output: {output_path}")
    console.print("  Press Ctrl+C to stop capture.\n")

    proxy_proc = subprocess.Popen(cmd)
    time.sleep(1)

    chrome_proc = subprocess.Popen(
        chrome_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        proxy_proc.wait()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping capture...[/yellow]")
        proxy_proc.send_signal(signal.SIGINT)
        chrome_proc.terminate()
        proxy_proc.wait(timeout=5)
        chrome_proc.wait(timeout=5)

    flows = read_capture_jsonl(str(output_path)) if output_path.exists() else []
    console.print(
        f"\n  Captured [bold]{len(flows)}[/bold] classified flows → {output_path}\n"
    )

# src/apisniff/recon.py
from __future__ import annotations

import json
import os
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
    f.write(flow.to_jsonl() + "\n")
    f.flush()


def read_capture_jsonl(path: str) -> list[CapturedFlow]:
    flows: list[CapturedFlow] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            flows.append(CapturedFlow.from_dict(json.loads(line)))
    return flows


def detect_input_format(head: str) -> str:
    stripped = head.strip()
    if '"log"' in stripped and stripped.startswith("{"):
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

    env = {**os.environ, "APISNIFF_TARGET": domain, "APISNIFF_OUTPUT": str(output_path)}

    cmd = [
        sys.executable, "-m", "mitmproxy",
        "--listen-port", str(port),
        "--set", "console_eventlog_verbosity=error",
        "-s", str(addon_path),
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

    proxy_proc = subprocess.Popen(cmd, env=env)
    time.sleep(1)

    if proxy_proc.poll() is not None:
        console.print(
            f"[red]mitmproxy exited with code {proxy_proc.returncode}[/red]"
        )
        return

    try:
        chrome_proc = subprocess.Popen(
            chrome_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        console.print("[yellow]Chrome not found — open a browser manually[/yellow]")
        console.print(f"  Set proxy to http://127.0.0.1:{port}")
        chrome_proc = None

    try:
        proxy_proc.wait()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping capture...[/yellow]")
        proxy_proc.send_signal(signal.SIGINT)
        if chrome_proc:
            chrome_proc.terminate()
        proxy_proc.wait(timeout=5)
        if chrome_proc:
            chrome_proc.wait(timeout=5)

    flows = read_capture_jsonl(str(output_path)) if output_path.exists() else []
    console.print(
        f"\n  Captured [bold]{len(flows)}[/bold] classified flows → {output_path}\n"
    )

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

from apisniff.models import CapturedFlow, SessionStats

_CAPTURES_DIR = Path.home() / "apisniff-captures"

stderr = Console(stderr=True)


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
    bundle_dir = _CAPTURES_DIR / f"{safe_domain}_{ts}"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    output_path = bundle_dir / "flows.jsonl"

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

    stderr.print(f"\n[bold]apisniff recon[/bold] — {domain}")
    stderr.print(f"  Proxy: 127.0.0.1:{port}")
    stderr.print(f"  Bundle: {bundle_dir}")
    stderr.print("  Press Ctrl+C to stop capture.\n")

    proxy_proc = subprocess.Popen(cmd, env=env)
    time.sleep(1)

    if proxy_proc.poll() is not None:
        stderr.print(
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
        stderr.print("[yellow]Chrome not found — open a browser manually[/yellow]")
        stderr.print(f"  Set proxy to http://127.0.0.1:{port}")
        chrome_proc = None

    try:
        proxy_proc.wait()
    except KeyboardInterrupt:
        stderr.print("\n[yellow]Stopping capture...[/yellow]")
        proxy_proc.send_signal(signal.SIGINT)
        if chrome_proc:
            chrome_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
        if chrome_proc:
            try:
                chrome_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                chrome_proc.kill()

    flows = read_capture_jsonl(str(output_path)) if output_path.exists() else []

    session_stats = None
    session_path = bundle_dir / "session.json"
    try:
        session_stats = SessionStats.from_dict(json.loads(session_path.read_text()))
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, KeyError):
        stderr.print("[yellow]Warning: session.json corrupted, skipping drop stats[/yellow]")

    if not flows:
        stderr.print(f"\n  No flows captured → {bundle_dir}\n")
        return

    from apisniff.auth import cookies_to_cookiejar, detect_auth, extract_cookies
    auth_patterns = detect_auth(flows)
    cookies = extract_cookies(flows)

    # Response-derived only — request cookies lack authoritative scope
    cookies_txt = cookies_to_cookiejar(cookies)
    if cookies_txt:
        cookies_path = bundle_dir / "cookies.txt"
        cookies_path.write_text(cookies_txt)
        stderr.print(f"  Cookies: {cookies_path}")

    import asyncio

    from apisniff.probe import fetch_graphql_schema
    gql_flows = [f for f in flows if "graphql" in f.path.lower()]
    gql_paths = sorted({f.path for f in gql_flows})
    # Schema fetch may require auth — forward headers from a captured GraphQL flow
    gql_headers: dict[str, str] = {}
    if gql_flows:
        sample = gql_flows[0].request_headers
        for hdr in ("authorization", "cookie", "x-api-key"):
            if hdr in sample:
                gql_headers[hdr] = sample[hdr]
    for gql_path in gql_paths:
        schema_url = f"https://{domain}{gql_path}"
        schema = asyncio.run(fetch_graphql_schema(schema_url, headers=gql_headers or None))
        if schema:
            schema_path = bundle_dir / "graphql-schema.json"
            schema_path.write_text(json.dumps(schema, indent=2))
            stderr.print(f"  GraphQL schema: {schema_path}")
            break  # one schema per session is enough

    from apisniff.models import ProbeResult
    from apisniff.vendors import load_signatures, match_vendors
    probe_results = [
        ProbeResult(
            label="captured", status=f.response_status,
            headers=f.response_headers, body=f.response_body,
            elapsed_ms=0.0, error=None,
        )
        for f in flows
    ]
    sigs = load_signatures()
    vendors = match_vendors(probe_results, sigs)

    from apisniff.report import generate_report
    report = generate_report(
        domain=domain, flows=flows, session_stats=session_stats,
        vendors=vendors, auth_patterns=auth_patterns, cookies=cookies,
    )

    report_path = bundle_dir / "report.md"
    report_path.write_text(report)

    from rich.markdown import Markdown
    stderr.print(Markdown(report))
    stderr.print(f"\n  Report: {report_path}")
    stderr.print(f"  Captured [bold]{len(flows)}[/bold] classified flows → {bundle_dir}\n")

# src/apisniff/recon.py
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

from rich.console import Console

from apisniff.models import CapturedFlow, SessionStats

CAPTURES_DIR = Path.home() / "apisniff-captures"

stderr = Console(stderr=True)


def safe_bundle_name(domain: str) -> str:
    return domain.replace(".", "-").replace("/", "-")


def find_latest_bundle(domain: str) -> Path | None:
    safe = safe_bundle_name(domain)
    candidates = sorted(
        (p for p in CAPTURES_DIR.glob(f"{safe}_*") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


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
            try:
                flows.append(CapturedFlow.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError):
                continue
    return flows


def detect_input_format(head: str) -> str:
    stripped = head.strip()
    if '"log"' in stripped and stripped.startswith("{"):
        return "har"
    if stripped.startswith("{") and '"method"' in stripped:
        return "jsonl"
    if "<?xml" in stripped and "<items" in stripped:
        return "burp"
    return "unknown"


def load_flows(path: str) -> tuple[list[CapturedFlow], str]:
    """Load flows from HAR, Burp XML, or JSONL file. Returns (flows, format)."""
    p = Path(path)
    text = p.read_text()
    fmt = detect_input_format(text[:1024])
    if fmt == "har":
        from apisniff.adapters.har import har_to_flows
        flows = har_to_flows(text)
    elif fmt == "burp":
        from apisniff.adapters.burp import burp_to_flows
        flows = burp_to_flows(text)
    elif fmt == "jsonl":
        flows = read_capture_jsonl(path)
    else:
        flows = []
    return flows, fmt


def _post_process_bundle(
    domain: str,
    flows: list[CapturedFlow],
    bundle_dir: Path,
    session_stats: SessionStats | None,
    *,
    fetch_graphql: bool = True,
) -> str:
    """Auth, cookies, GraphQL, vendors, report. Returns report markdown."""
    import asyncio

    from apisniff.auth import cookies_to_cookiejar, detect_auth, extract_cookies
    auth_patterns = detect_auth(flows)
    cookies = extract_cookies(flows)

    cookies_txt = cookies_to_cookiejar(cookies)
    if cookies_txt:
        cookies_path = bundle_dir / "cookies.txt"
        cookies_path.write_text(cookies_txt)
        stderr.print(f"  Cookies: {cookies_path}")

    if fetch_graphql:
        from apisniff.probe import fetch_graphql_schema
        gql_flows = [f for f in flows if "graphql" in f.path.lower()]
        gql_paths = sorted({f.path for f in gql_flows})
        gql_headers: dict[str, str] = {}
        if gql_flows:
            sample = gql_flows[0].request_headers
            for hdr in ("authorization", "cookie", "x-api-key"):
                if hdr in sample:
                    gql_headers[hdr] = sample[hdr]
        for gql_path in gql_paths:
            schema_url = f"https://{domain}{gql_path}"
            schema = asyncio.run(
                fetch_graphql_schema(schema_url, headers=gql_headers or None)
            )
            if schema:
                schema_path = bundle_dir / "graphql-schema.json"
                schema_path.write_text(json.dumps(schema, indent=2))
                stderr.print(f"  GraphQL schema: {schema_path}")
                break

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
    return report


def run_recon(
    domain: str,
    port: int = 8080,
    proxy: str | None = None,
    json_output: bool = False,
) -> None:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    CAPTURES_DIR.chmod(0o700)
    ts = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M")
    safe_domain = safe_bundle_name(domain)
    bundle_dir = CAPTURES_DIR / f"{safe_domain}_{ts}"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir.chmod(0o700)
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

    report = _post_process_bundle(domain, flows, bundle_dir, session_stats)
    from rich.markdown import Markdown
    stderr.print(Markdown(report))
    stderr.print(f"\n  Report: {bundle_dir / 'report.md'}")
    stderr.print(f"  Captured [bold]{len(flows)}[/bold] classified flows → {bundle_dir}\n")


def run_analyze(
    input_file: str,
    domain: str | None = None,
    json_output: bool = False,
    output_dir: str | None = None,
    fetch_graphql: bool = False,
) -> None:
    """Offline analysis: load a traffic capture, classify, extract everything."""
    # 1. Load flows
    flows, fmt = load_flows(input_file)
    if not flows:
        stderr.print("[yellow]No flows found in input file.[/yellow]")
        return

    # 2. Auto-detect domain from the flows if not provided
    if domain is None:
        from apisniff.classify import extract_registered_domain
        host_counter: Counter[str] = Counter(
            extract_registered_domain(f.host) for f in flows if f.host
        )
        if not host_counter:
            stderr.print("[red]Cannot determine domain — use --domain.[/red]")
            return
        most_common = host_counter.most_common(2)
        top_domain, top_count = most_common[0]
        if len(most_common) > 1:
            _, second_count = most_common[1]
            if top_count < 2 * second_count:
                stderr.print(
                    f"[yellow]Warning: ambiguous domain — "
                    f"top '{top_domain}' ({top_count}) is not 2x second "
                    f"({second_count}). Use --domain to specify explicitly.[/yellow]"
                )
        domain = top_domain

    # 3. Classify (HAR/Burp) or skip (JSONL)
    kept_flows: list[CapturedFlow]
    drop_counts: dict[str, int] = {}

    if fmt in ("har", "burp"):
        from apisniff.classify import Classifier
        classifier = Classifier(target_domain=domain)
        kept_flows = []
        for flow in flows:
            result = classifier.classify(flow)
            if result.action == "keep":
                if result.flow is not None:
                    kept_flows.append(result.flow)
            else:
                drop_counts[result.category] = drop_counts.get(result.category, 0) + 1
    elif fmt == "jsonl":
        kept_flows = flows
    else:
        stderr.print(f"[red]Unrecognised format for {input_file}[/red]")
        return

    session_stats = SessionStats(
        domain=domain,
        started_at=datetime.now(tz=UTC).isoformat(),
        duration_seconds=0.0,
        total_flows=len(flows),
        kept_flows=len(kept_flows),
        dropped=drop_counts,
    )

    # 4. Create bundle dir, write flows.jsonl and session.json
    if output_dir:
        bundle_dir = Path(output_dir)
    else:
        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        CAPTURES_DIR.chmod(0o700)
        ts = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M")
        safe_domain = safe_bundle_name(domain)
        bundle_dir = CAPTURES_DIR / f"{safe_domain}_{ts}_analyze"

    bundle_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir.chmod(0o700)

    flows_path = bundle_dir / "flows.jsonl"
    with open(flows_path, "w") as fh:
        for flow in kept_flows:
            fh.write(flow.to_jsonl() + "\n")

    session_path = bundle_dir / "session.json"
    session_path.write_text(json.dumps(session_stats.to_dict(), indent=2))

    report = _post_process_bundle(
        domain, kept_flows, bundle_dir, session_stats,
        fetch_graphql=fetch_graphql,
    )

    if json_output:
        sys.stdout.write(json.dumps(session_stats.to_dict(), indent=2) + "\n")
    else:
        from rich.markdown import Markdown
        stderr.print(Markdown(report))

    stderr.print(f"\n  Report: {bundle_dir / 'report.md'}")
    stderr.print(f"  Analyzed [bold]{len(kept_flows)}[/bold] flows → {bundle_dir}\n")

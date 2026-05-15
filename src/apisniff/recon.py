# src/apisniff/recon.py
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from apisniff.bundle import (
    CAPTURES_DIR,
    detect_input_format,  # noqa: F401 — re-exported for backwards compat
    load_flows,
    read_capture_jsonl,
    safe_bundle_name,
    write_flow_jsonl,  # noqa: F401 — re-exported for backwards compat
)
from apisniff.models import CapturedFlow, SessionStats, normalize_path

stderr = Console(stderr=True)


@dataclass
class _BundleResult:
    report_md: str
    vendors: list
    auth_patterns: list
    cookies: list
    cookies_path: Path | None
    graphql_schema_path: Path | None


_DROP_DESCRIPTIONS = {
    "options": "CORS preflight (OPTIONS) requests",
    "telemetry": "Telemetry, analytics, logging, or beacon traffic",
    "third_party_api": "API-shaped traffic on third-party hosts",
    "static": "Static files (images, CSS, JS, fonts)",
    "non_api": "Non-API page or asset traffic",
    "antibot": "Bot-defense sensor or challenge traffic",
    "captcha": "Captcha or browser challenge traffic",
}

_AUTH_TYPE_DESCRIPTIONS = {
    "bearer": "OAuth2 / JWT bearer token in Authorization header",
    "basic": "HTTP Basic authentication in Authorization header",
    "api_key_header": "API key sent in a custom request header",
    "api_key_query": "API key sent as a URL query parameter",
    "session_cookie": "Server-side session identified by a known session cookie name",
    "token_endpoint": "Request to a known token/auth endpoint path",
}

_AUTH_TYPE_LABELS = {
    "bearer": "Bearer token",
    "basic": "Basic auth",
    "api_key_header": "API key header",
    "api_key_query": "API key query parameter",
    "session_cookie": "session cookie",
    "token_endpoint": "token endpoint",
}


def _display_name(value: str) -> str:
    return value.replace("_", " ").title()


def _summarize_names(names: list[str]) -> str:
    if not names:
        return ""
    if len(names) <= 3:
        return ", ".join(names)
    return ", ".join(names[:3]) + f", +{len(names) - 3} more"


def _top_endpoints(flows: list[CapturedFlow], limit: int = 15) -> list[dict]:
    counts: Counter[tuple[str, str]] = Counter()
    for flow in flows:
        counts[(flow.method.upper(), normalize_path(flow.path))] += 1
    return [
        {"method": method, "path": path, "count": count}
        for (method, path), count in counts.most_common(limit)
    ]


def _build_analyze_interpretation(
    domain: str,
    session_stats: SessionStats,
    result: _BundleResult,
) -> str:
    parts = [
        f"Analyzed {session_stats.total_flows} flows for {domain}, "
        f"kept {session_stats.kept_flows} API calls."
    ]

    vendor_names = [_display_name(v.vendor) for v in result.vendors]
    if vendor_names:
        parts.append(
            f"Found {len(vendor_names)} vendors ({_summarize_names(vendor_names)})."
        )
    else:
        parts.append("No vendors detected.")

    auth_names = [
        _AUTH_TYPE_LABELS.get(p.auth_type, p.auth_type.replace("_", " "))
        for p in result.auth_patterns
    ]
    if auth_names:
        parts.append(
            f"{len(auth_names)} auth patterns detected ({_summarize_names(auth_names)})."
        )
    else:
        parts.append("No auth patterns detected.")

    return " ".join(parts)


def _fallback_session_stats(domain: str, flows: list[CapturedFlow]) -> SessionStats:
    return SessionStats(
        domain=domain,
        started_at=datetime.now(tz=UTC).isoformat(),
        duration_seconds=0.0,
        total_flows=len(flows),
        kept_flows=len(flows),
        dropped={},
    )


def _analyze_to_dict(
    domain: str,
    session_stats: SessionStats | None,
    result: _BundleResult,
    kept_flows: list[CapturedFlow],
    bundle_dir: Path,
) -> dict:
    stats = session_stats or _fallback_session_stats(domain, kept_flows)
    stats_dict = stats.to_dict()

    return {
        "schema_version": 1,
        "interpretation": _build_analyze_interpretation(domain, stats, result),
        **stats_dict,
        "drop_descriptions": dict(_DROP_DESCRIPTIONS),
        "vendors": [
            {"vendor": v.vendor, "confidence": v.confidence, "signals": v.signals}
            for v in result.vendors
        ],
        "auth_patterns": [p.to_dict() for p in result.auth_patterns],
        "top_endpoints": _top_endpoints(kept_flows),
        "auth_type_descriptions": dict(_AUTH_TYPE_DESCRIPTIONS),
        "bundle_dir": str(bundle_dir),
        "report_path": str(bundle_dir / "report.md"),
        "cookies_path": str(result.cookies_path) if result.cookies_path else None,
        "graphql_schema_path": (
            str(result.graphql_schema_path) if result.graphql_schema_path else None
        ),
    }


def _post_process_bundle(
    domain: str,
    flows: list[CapturedFlow],
    bundle_dir: Path,
    session_stats: SessionStats | None,
    *,
    fetch_graphql: bool = True,
) -> _BundleResult:
    """Auth, cookies, GraphQL, vendors, report. Returns structured result."""
    import asyncio

    from apisniff.auth import cookies_to_cookiejar, detect_auth, extract_cookies
    auth_patterns = detect_auth(flows)
    cookies = extract_cookies(flows)

    cookies_path: Path | None = None
    cookies_txt = cookies_to_cookiejar(cookies)
    if cookies_txt:
        cookies_path = bundle_dir / "cookies.txt"
        cookies_path.write_text(cookies_txt)

    graphql_schema_path: Path | None = None
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
                graphql_schema_path = bundle_dir / "graphql-schema.json"
                graphql_schema_path.write_text(json.dumps(schema, indent=2))
                break

    from apisniff.vendors import flows_to_probe_results, load_signatures, match_vendors
    vendors = match_vendors(flows_to_probe_results(flows), load_signatures())

    from apisniff.report import generate_report
    report = generate_report(
        domain=domain, flows=flows, session_stats=session_stats,
        vendors=vendors, auth_patterns=auth_patterns, cookies=cookies,
    )
    report_path = bundle_dir / "report.md"
    report_path.write_text(report)

    return _BundleResult(
        report_md=report,
        vendors=vendors,
        auth_patterns=auth_patterns,
        cookies=cookies,
        cookies_path=cookies_path,
        graphql_schema_path=graphql_schema_path,
    )


_MITMPROXY_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
_SYSTEM_KEYCHAIN = Path("/Library/Keychains/System.keychain")
_LOGIN_KEYCHAIN = Path.home() / "Library" / "Keychains" / "login.keychain-db"


def _is_ca_trusted() -> bool:
    for keychain in (_SYSTEM_KEYCHAIN, _LOGIN_KEYCHAIN):
        result = subprocess.run(
            ["security", "find-certificate", "-c", "mitmproxy", str(keychain)],
            capture_output=True,
        )
        if result.returncode == 0:
            return True
    return False


def _install_ca_trust(console: Console) -> bool:
    if not _MITMPROXY_CA.exists():
        console.print("[red]mitmproxy CA not found — cannot auto-install certificate[/red]")
        return False

    console.print("\n[bold]One-time setup: HTTPS certificate[/bold]\n")
    console.print(
        "  apisniff uses [link=https://mitmproxy.org]mitmproxy[/link], a widely-used"
        " open-source proxy, to read HTTPS traffic.\n"
        "  A local certificate is generated on your machine and stays on your machine.\n"
        "  Trusting it lets the proxied browser share HTTPS details with apisniff.\n"
    )
    console.print(
        "  [bold]What this does not affect:[/bold] your normal browser, other apps,\n"
        "  or any traffic outside this proxy session.\n"
    )
    console.print(
        f"  [dim]$ sudo security add-trusted-cert -d -r trustRoot \\\n"
        f"      -k /Library/Keychains/System.keychain {_MITMPROXY_CA}[/dim]\n"
    )
    console.print(
        "  [dim]To remove later: Keychain Access → search 'mitmproxy' → delete[/dim]\n"
    )
    console.print("  macOS will ask for your password.\n")

    result = subprocess.run([
        "sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
        "-k", str(_SYSTEM_KEYCHAIN), str(_MITMPROXY_CA),
    ])
    if result.returncode == 0:
        console.print("  [green]Certificate trusted.[/green]\n")
        return True
    console.print("  [red]Certificate install failed.[/red]")
    console.print("  Fallback: open [bold]http://mitm.it[/bold] in the proxied Chrome window.\n")
    return False


def _normalize_target(raw: str) -> tuple[str, str]:
    """Return (bare_domain, launch_url) from user input that may include a scheme or path."""
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        domain = parsed.netloc or parsed.path.split("/")[0]
        return domain, raw
    return raw, f"https://{raw}"


def run_recon(
    domain: str,
    port: int = 8080,
    proxy: str | None = None,
    json_output: bool = False,
) -> None:
    domain, launch_url = _normalize_target(domain)
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
        sys.executable, "-c",
        "from mitmproxy.tools.main import mitmdump; mitmdump()",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--quiet",
        "-s", str(addon_path),
    ]
    if proxy:
        cmd.extend(["--mode", f"upstream:{proxy}"])

    stderr.print(f"\n[bold]apisniff recon[/bold] — {domain}")
    stderr.print(f"  Proxy: 127.0.0.1:{port}")
    stderr.print(f"  Bundle: {bundle_dir}")
    stderr.print("  Press Ctrl+C to stop capture.\n")

    proxy_proc = subprocess.Popen(
        cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    chrome_profile = None
    chrome_proc = None
    try:
        time.sleep(1)

        if proxy_proc.poll() is not None:
            stderr.print(
                f"[red]mitmproxy exited with code {proxy_proc.returncode}[/red]"
            )
            return

        if not _is_ca_trusted():
            _install_ca_trust(stderr)

        chrome_profile = Path(tempfile.mkdtemp(prefix="apisniff-chrome-"))
        chrome_cmd = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            f"--proxy-server=http://127.0.0.1:{port}",
            f"--user-data-dir={chrome_profile}",
            "--no-first-run",
            "--no-default-browser-check",
            launch_url,
        ]

        try:
            chrome_proc = subprocess.Popen(
                chrome_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            stderr.print("[yellow]Chrome not found — open a browser manually[/yellow]")
            stderr.print(f"  Set proxy to http://127.0.0.1:{port}")

        try:
            proxy_proc.wait()
        except KeyboardInterrupt:
            stderr.print("\n[yellow]Stopping capture...[/yellow]")
            proxy_proc.send_signal(signal.SIGINT)
            try:
                proxy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
    finally:
        if proxy_proc.poll() is None:
            proxy_proc.send_signal(signal.SIGINT)
            try:
                proxy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
        if chrome_proc:
            if chrome_proc.poll() is None:
                chrome_proc.terminate()
            try:
                chrome_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                chrome_proc.kill()
                chrome_proc.wait()
        if chrome_profile is not None:
            shutil.rmtree(chrome_profile, ignore_errors=True)

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

    result = _post_process_bundle(domain, flows, bundle_dir, session_stats)
    if json_output:
        data = _analyze_to_dict(domain, session_stats, result, flows, bundle_dir)
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
    else:
        from apisniff.output import render_recon
        render_recon(
            domain=domain,
            session_stats=session_stats,
            flows=flows,
            vendors=result.vendors,
            auth_patterns=result.auth_patterns,
            cookies=result.cookies,
            bundle_dir=bundle_dir,
            cookies_path=result.cookies_path,
            graphql_schema_path=result.graphql_schema_path,
            console=stderr,
        )


def run_analyze(
    input_file: str,
    domain: str | None = None,
    json_output: bool = False,
    output_dir: str | None = None,
    fetch_graphql: bool = False,
) -> None:
    """Offline analysis: load a traffic capture, classify, extract everything."""
    try:
        flows, fmt = load_flows(input_file)
    except ValueError as e:
        stderr.print(f"[red]{e}[/red]")
        raise SystemExit(1) from None
    if not flows:
        stderr.print("[yellow]No flows found in input file.[/yellow]")
        return

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

    kept_flows: list[CapturedFlow]
    drop_counts: dict[str, int] = {}

    if fmt in ("har", "burp"):
        from apisniff.classify import Classifier
        classifier = Classifier(target_domain=domain)
        kept_flows = []
        for flow in flows:
            result = classifier.classify(flow)
            if result.action == "drop":
                drop_counts[result.category] = drop_counts.get(result.category, 0) + 1
                continue
            if result.flow is not None:
                kept_flows.append(result.flow)
    elif fmt == "jsonl":
        kept_flows = [flow for flow in flows if flow.method.upper() != "OPTIONS"]
    else:
        stderr.print(f"[red]Unrecognised format for {input_file}[/red]")
        return

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

    from apisniff.spec_classify import derive_surface_records
    from apisniff.surface import (
        IMPORTANT_SURFACE_CATEGORIES,
        write_capture_context,
        write_surface_metadata,
    )

    context, records = derive_surface_records(kept_flows, domain)
    write_capture_context(bundle_dir, context)
    write_surface_metadata(bundle_dir, records)
    classifications = [record["classification"] for record in records]
    openapi_candidate_flows = sum(
        1 for item in classifications
        if item["category"] in {"business_api", "auth"}
    )
    surface_flows = sum(
        1 for item in classifications
        if item["category"] in IMPORTANT_SURFACE_CATEGORIES
        and item["category"] not in {"business_api", "auth"}
    )
    noise_flows = len(classifications) - openapi_candidate_flows - surface_flows

    session_path = bundle_dir / "session.json"
    if session_path.exists():
        try:
            session_stats = SessionStats.from_dict(json.loads(session_path.read_text()))
        except (json.JSONDecodeError, KeyError):
            session_stats = None
    else:
        session_stats = None
    if session_stats is None:
        session_stats = SessionStats(
            domain=domain,
            started_at=datetime.now(tz=UTC).isoformat(),
            duration_seconds=0.0,
            total_flows=len(flows),
            kept_flows=len(kept_flows),
            dropped=drop_counts,
            captured_flows=len(kept_flows),
            openapi_candidate_flows=openapi_candidate_flows,
            surface_flows=surface_flows,
            noise_flows=noise_flows,
        )
        session_path.write_text(json.dumps(session_stats.to_dict(), indent=2))

    flows_path = bundle_dir / "flows.jsonl"
    if Path(input_file).resolve() != flows_path.resolve():
        with open(flows_path, "w") as fh:
            for flow in kept_flows:
                fh.write(flow.to_jsonl() + "\n")

    result = _post_process_bundle(
        domain, kept_flows, bundle_dir, session_stats,
        fetch_graphql=fetch_graphql,
    )

    if json_output:
        data = _analyze_to_dict(domain, session_stats, result, kept_flows, bundle_dir)
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        stderr.print(f"\n  Report: {bundle_dir / 'report.md'}")
        stderr.print(f"  Analyzed [bold]{len(kept_flows)}[/bold] flows → {bundle_dir}\n")
    else:
        from apisniff.output import render_recon
        render_recon(
            domain=domain,
            session_stats=session_stats,
            flows=kept_flows,
            vendors=result.vendors,
            auth_patterns=result.auth_patterns,
            cookies=result.cookies,
            bundle_dir=bundle_dir,
            cookies_path=result.cookies_path,
            graphql_schema_path=result.graphql_schema_path,
            command="analyze",
            console=stderr,
        )

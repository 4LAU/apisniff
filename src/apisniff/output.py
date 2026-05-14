from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import get_args

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apisniff.models import (
    CapturedFlow,
    ProbeAssessment,
    ProbeVerdict,
    ReplayAbort,
    ReplayCategory,
    ReplayResult,
)

_VERDICT_STYLES = {
    ProbeVerdict.NO_PROTECTION: ("green", "No Protection"),
    ProbeVerdict.CLIENT_DEPENDENT: ("yellow", "Client-Dependent"),
    ProbeVerdict.JS_CHALLENGE: ("red", "JS Challenge"),
    ProbeVerdict.FULL_BLOCK: ("red bold", "Full Block"),
}

_VERDICT_ICONS = {
    ProbeVerdict.NO_PROTECTION: "●",
    ProbeVerdict.CLIENT_DEPENDENT: "◐",
    ProbeVerdict.JS_CHALLENGE: "▲",
    ProbeVerdict.FULL_BLOCK: "■",
}

_PROBE_HINTS = {
    "naked": "raw client, bot UA",
    "impersonated": "Chrome TLS + Chrome UA",
    "tls_only": "Chrome TLS, bot UA",
}


def _latency_bar(ms: float, max_ms: float, width: int = 16) -> Text:
    if max_ms <= 0:
        return Text(f"{ms:.0f}ms")
    ratio = ms / max_ms
    filled = max(1, round(ratio * width))
    empty = width - filled

    if ms < 200:
        bar_style = "green"
    elif ms < 500:
        bar_style = "yellow"
    else:
        bar_style = "red"

    result = Text()
    result.append("█" * filled, style=bar_style)
    result.append("░" * empty, style="bright_black")
    result.append(f" {ms:.0f}ms", style=bar_style)
    return result


def _format_size(nbytes: int) -> str:
    if nbytes < 1024:
        return f"{nbytes}B"
    if nbytes < 10 * 1024:
        return f"{nbytes / 1024:.1f}KB"
    if nbytes < 1024 * 1024:
        return f"{nbytes // 1024}KB"
    return f"{nbytes / (1024 * 1024):.1f}MB"


def _get_header(headers: dict[str, str], name: str) -> str:
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return ""


def _extract_set_cookie_names(headers: dict[str, str]) -> list[str]:
    names: list[str] = []
    val = _get_header(headers, "set-cookie")
    if not val:
        return names
    for line in val.split("\n"):
        line = line.strip()
        if not line:
            continue
        name = line.split(";", 1)[0].split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def _error_label(error: str) -> str:
    e = error.lower()
    if "timeout" in e or "timed out" in e:
        return "TIMEOUT"
    if "reset" in e:
        return "RESET"
    if "refused" in e:
        return "REFUSED"
    if "ssl" in e or "certificate" in e or "tls" in e:
        return "SSL ERROR"
    if "dns" in e or "name resolution" in e or "nodename" in e:
        return "DNS ERROR"
    return "ERROR"


def _confidence_badge(confidence: str) -> Text:
    levels = {"low": 1, "medium": 2, "high": 3}
    styles = {"low": "dim", "medium": "yellow", "high": "red"}
    level = levels.get(confidence, 0)
    bar_style = styles.get(confidence, "")

    result = Text()
    result.append("█" * level, style=bar_style)
    result.append("░" * (3 - level), style="bright_black")
    result.append(f" {confidence.upper()}", style=f"bold {bar_style}")
    return result


def probe_to_dict(assessment: ProbeAssessment) -> dict:
    probes = {}
    for label, result in assessment.results.items():
        probes[label] = {
            "status": result.status,
            "elapsed_ms": result.elapsed_ms,
            "blocked": result.is_blocked,
            "challenge": result.is_challenge,
            "error": result.error,
        }

    vendors = [
        {"vendor": v.vendor, "confidence": v.confidence, "signals": v.signals}
        for v in assessment.vendors
    ]

    result: dict = {
        "url": assessment.url,
        "verdict": assessment.verdict.value,
        "recommendation": assessment.recommendation,
        "probes": probes,
        "vendors": vendors,
        "graphql": {
            "endpoints": assessment.graphql_endpoints,
            "introspection": assessment.graphql_introspection,
            "schema_path": assessment.graphql_schema_path,
        },
    }
    if assessment.rate_limit:
        result["rate_limit"] = {
            "requests_sent": assessment.rate_limit.requests_sent,
            "first_block_at": assessment.rate_limit.first_block_at,
            "block_status": assessment.rate_limit.block_status,
            "retry_after": assessment.rate_limit.retry_after,
            "median_ms": assessment.rate_limit.median_ms,
            "silent_throttle": assessment.rate_limit.silent_throttle,
        }
    return result


def probe_to_json(assessment: ProbeAssessment) -> str:
    return json.dumps(probe_to_dict(assessment), indent=2)


def render_probe(assessment: ProbeAssessment, console: Console | None = None) -> None:
    console = console or Console(stderr=True)

    style, label = _VERDICT_STYLES[assessment.verdict]
    icon = _VERDICT_ICONS[assessment.verdict]

    if assessment.verdict == ProbeVerdict.NO_PROTECTION and assessment.vendors:
        label = "Passthrough"

    # --- Probe data (probes + vendors in one panel) ---
    console.print()

    max_ms = max(
        (r.elapsed_ms for r in assessment.results.values()),
        default=1.0,
    )

    body_sizes: dict[str, int] = {}
    for lbl, r in assessment.results.items():
        if not r.error:
            body_sizes[lbl] = len(r.body) if r.body else 0
    max_body = max(body_sizes.values(), default=0)
    size_mismatch = max_body > 0 and any(
        s < max_body * 0.25 for s in body_sizes.values()
    )

    table = Table(
        show_header=True, header_style="bold", expand=True,
        box=box.SIMPLE_HEAD, padding=(0, 1), show_edge=False,
    )
    table.add_column("Probe", style="cyan", min_width=14)
    table.add_column("", style="dim", ratio=1)
    table.add_column("Latency", min_width=24)
    table.add_column("Size", justify="right", min_width=7)
    table.add_column("Result", justify="center", min_width=14)

    for probe_name in ("naked", "impersonated", "tls_only"):
        result = assessment.results[probe_name]
        hint = _PROBE_HINTS.get(probe_name, "")

        if result.error:
            err_label = _error_label(result.error)
            result_str = Text(f" {err_label} ", style="bold white on red")
            latency = _latency_bar(result.elapsed_ms, max_ms)
            size_cell = Text("—", style="dim")
        elif result.is_challenge:
            result_str = Text(f" {result.status} CHALLENGE ", style="bold black on yellow")
            latency = _latency_bar(result.elapsed_ms, max_ms)
            bsize = len(result.body) if result.body else 0
            size_cell = Text(_format_size(bsize), style="dim")
        elif result.is_blocked:
            result_str = Text(f" {result.status} BLOCKED ", style="bold white on red")
            latency = _latency_bar(result.elapsed_ms, max_ms)
            bsize = len(result.body) if result.body else 0
            size_style = "red" if size_mismatch and max_body > 0 and bsize < max_body * 0.25 else "dim"
            size_cell = Text(_format_size(bsize), style=size_style)
        else:
            result_str = Text(f" {result.status} PASS ", style="bold black on bright_green")
            latency = _latency_bar(result.elapsed_ms, max_ms)
            bsize = len(result.body) if result.body else 0
            size_style = "red" if size_mismatch and max_body > 0 and bsize < max_body * 0.25 else "dim"
            size_cell = Text(_format_size(bsize), style=size_style)

        table.add_row(probe_name, hint, latency, size_cell, result_str)

    panel_parts: list[object] = [table]

    if assessment.vendors:
        panel_parts.append(Text())
        vendor_table = Table(
            show_header=False, box=None, padding=(0, 1), show_edge=False,
        )
        vendor_table.add_column("Name", style="cyan")
        vendor_table.add_column("Confidence")
        vendor_table.add_column("Signals", style="dim")
        for v in assessment.vendors:
            vendor_table.add_row(
                v.vendor.replace("_", " ").title(),
                _confidence_badge(v.confidence),
                ", ".join(v.signals),
            )
        panel_parts.append(vendor_table)

    signal_lines: list[tuple[str, str | Text]] = []

    servers: list[str] = []
    for r in assessment.results.values():
        if r.error:
            continue
        s = _get_header(r.headers, "server")
        if s and s not in servers:
            servers.append(s)
        powered = _get_header(r.headers, "x-powered-by")
        if powered and powered not in servers:
            servers.append(powered)
    if servers:
        signal_lines.append(("Server", " · ".join(servers)))

    vias: list[str] = []
    for r in assessment.results.values():
        if r.error:
            continue
        v = _get_header(r.headers, "via")
        if v and v not in vias:
            vias.append(v)
    if vias:
        signal_lines.append(("Via", " · ".join(vias)))

    all_cookies: list[str] = []
    for r in assessment.results.values():
        if r.error:
            continue
        for name in _extract_set_cookie_names(r.headers):
            if name not in all_cookies:
                all_cookies.append(name)
    if all_cookies:
        signal_lines.append(("Cookies", " · ".join(all_cookies)))

    cors_per_probe: dict[str, str] = {}
    for lbl, r in assessment.results.items():
        if r.error:
            continue
        origin = _get_header(r.headers, "access-control-allow-origin")
        if origin:
            cors_per_probe[lbl] = origin
    if cors_per_probe:
        unique_origins = set(cors_per_probe.values())
        if len(unique_origins) == 1:
            cors_text = f"Origin: {next(iter(unique_origins))}"
            for r in assessment.results.values():
                methods = _get_header(r.headers, "access-control-allow-methods")
                if methods:
                    cors_text += f"    Methods: {methods}"
                    break
            signal_lines.append(("CORS", cors_text))
        else:
            parts = [f"{lbl}: {orig}" for lbl, orig in cors_per_probe.items()]
            signal_lines.append(("CORS", "  ".join(parts)))

    cache_vals: list[str] = []
    vary_items: list[str] = []
    for r in assessment.results.values():
        if r.error:
            continue
        cc = _get_header(r.headers, "cache-control")
        if cc and cc not in cache_vals:
            cache_vals.append(cc)
        vary = _get_header(r.headers, "vary")
        if vary:
            for item in vary.split(","):
                item = item.strip()
                if item and item not in vary_items:
                    vary_items.append(item)
    if cache_vals or vary_items:
        parts = []
        if cache_vals:
            parts.append(" · ".join(cache_vals))
        if vary_items:
            parts.append(f"Vary: {', '.join(vary_items)}")
        signal_lines.append(("Cache", "    ".join(parts)))

    content_types: dict[str, str] = {}
    for lbl, r in assessment.results.items():
        if r.error:
            continue
        ct = _get_header(r.headers, "content-type")
        if ct:
            content_types[lbl] = ct.split(";")[0].strip()
    if len(set(content_types.values())) > 1:
        parts = [
            f"{lbl}: {ct}"
            for lbl, ct in content_types.items()
        ]
        signal_lines.append(("Content", "  ".join(parts)))

    if signal_lines:
        panel_parts.append(Text())
        signal_table = Table(
            show_header=False, box=None, padding=(0, 1), show_edge=False,
        )
        signal_table.add_column("Label", style="dim", min_width=8)
        signal_table.add_column("Value")
        for sig_label, sig_value in signal_lines:
            signal_table.add_row(sig_label, sig_value)
        panel_parts.append(signal_table)

    console.print(Panel(
        Group(*panel_parts),
        title=f"[bold]apisniff probe[/bold]  [dim]{assessment.url}[/dim]",
        box=box.ROUNDED,
        expand=True,
        padding=(1, 1),
    ))

    # --- GraphQL (compact, no panel) ---
    if assessment.graphql_endpoints:
        if assessment.graphql_introspection:
            gql_status = "[green]introspection enabled[/green]"
        else:
            gql_status = "[yellow]introspection disabled[/yellow]"
        for ep in assessment.graphql_endpoints:
            console.print(f"  GraphQL  [cyan]{ep}[/cyan]  {gql_status}")
        if assessment.graphql_schema_path:
            try:
                from pathlib import Path
                schema_data = json.loads(Path(assessment.graphql_schema_path).read_text())
                types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
                total_fields = sum(
                    len(t.get("fields", []) or []) for t in types
                )
                console.print(
                    f"  GraphQL  [bold]{len(types)}[/bold] types, "
                    f"[bold]{total_fields}[/bold] fields"
                )
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                pass

    # --- Rate limiting (compact, no panel) ---
    if assessment.rate_limit:
        rl = assessment.rate_limit
        if rl.first_block_at is not None:
            console.print(
                f"  Rate limit  blocked at request [bold red]{rl.first_block_at}[/bold red]"
                f" [dim](HTTP {rl.block_status})[/dim]"
            )
            if rl.retry_after:
                console.print(f"  [dim]Retry-After: {rl.retry_after}s[/dim]")
        elif rl.silent_throttle:
            console.print(
                "  Rate limit  [yellow]possible silent throttle[/yellow]"
                " [dim](response times >2x in second half)[/dim]"
            )
        else:
            console.print(
                f"  Rate limit  [green]none detected[/green]"
                f" [dim]in {rl.requests_sent} requests[/dim]"
            )
        console.print(
            f"  [dim]Median: {rl.median_ms:.0f}ms"
            f" over {rl.requests_sent} requests[/dim]"
        )

    # --- Verdict (dominant element) ---
    console.print()
    verdict_text = Text()
    verdict_text.append(f" {icon} ", style=f"bold {style}")
    if assessment.vendors:
        vendor_names = ", ".join(
            v.vendor.replace("_", " ").title() for v in assessment.vendors
        )
        verdict_text.append(f"{vendor_names} ", style=f"bold {style}")
    verdict_text.append(label, style=f"bold {style}")
    console.print(Align.center(verdict_text))
    console.print()

    # --- Recommendation (the payoff) ---
    console.print(Panel(
        Text(assessment.recommendation),
        border_style=style,
        box=box.ROUNDED,
        padding=(0, 1),
        expand=True,
    ))
    console.print()


_REPLAY_SYMBOL = {
    "match": "✓",
    "drift": "~",
    "auth_expired": "✗",
    "blocked": "✗",
    "error": "✗",
}

_REPLAY_STYLE = {
    "match": "green",
    "drift": "yellow",
    "auth_expired": "red",
    "blocked": "red",
    "error": "red",
}

_CATEGORY_LABEL = {
    "match": "shape:match",
    "drift": "shape:drift",
    "auth_expired": "AUTH EXPIRED",
    "blocked": "BLOCKED",
    "error": "ERROR",
}


_CATEGORIES = get_args(ReplayCategory)


def _tally_results(results: list[ReplayResult]) -> dict[str, int]:
    counts: dict[str, int] = {c: 0 for c in _CATEGORIES}
    for r in results:
        counts[r.category] = counts.get(r.category, 0) + 1
    return counts


def _auth_label(headers: dict[str, str]) -> str:
    has_bearer = any(
        k.lower() == "authorization" and v.lower().startswith("bearer")
        for k, v in headers.items()
    )
    has_cookie = any(k.lower() == "cookie" for k in headers)
    parts = []
    if has_bearer:
        parts.append("bearer")
    if has_cookie:
        parts.append("cookie")
    return "+".join(parts) if parts else "none"


def render_replay(
    results: list[ReplayResult],
    console: Console,
    abort: ReplayAbort | None = None,
) -> None:
    console.print()
    counts = _tally_results(results)

    domain = results[0].original_flow.host if results else ""

    table = Table(
        show_header=True, header_style="bold", expand=True,
        box=box.SIMPLE_HEAD, padding=(0, 1), show_edge=False,
    )
    table.add_column("", min_width=1)
    table.add_column("Method", style="bold", min_width=6)
    table.add_column("Path", ratio=1)
    table.add_column("Status", justify="center", min_width=10)
    table.add_column("Result", min_width=14)
    table.add_column("Time", justify="right", style="dim", min_width=7)

    for r in results:
        cat = r.category
        sym = _REPLAY_SYMBOL.get(cat, "?")
        cat_style = _REPLAY_STYLE.get(cat, "")
        label = _CATEGORY_LABEL.get(cat, cat)

        orig_status = r.original_flow.response_status
        rep_status = r.replayed_status if r.replayed_status is not None else "err"

        path_cell = Text(r.original_flow.path, style="cyan")
        if cat == "drift" and r.body_shape_diff:
            for key, change in r.body_shape_diff.items():
                if isinstance(change, dict):
                    path_cell.append("\n")
                    if change.get("was") is None:
                        path_cell.append(f"  + {key}", style="green")
                    elif change.get("now") is None:
                        path_cell.append(f"  - {key}", style="red")
                    else:
                        path_cell.append(f"  ~ {key}", style="yellow")

        status_cell = Text()
        status_cell.append(str(orig_status), style="dim")
        status_cell.append(" → ", style="dim")
        status_cell.append(str(rep_status), style=cat_style)

        table.add_row(
            Text(sym, style=cat_style),
            r.original_flow.method.upper(),
            path_cell,
            status_cell,
            Text(label, style=cat_style),
            f"{r.elapsed_ms:.0f}ms",
        )

    panel_parts: list[object] = [table]

    if abort:
        panel_parts.append(Text())
        panel_parts.append(Text(
            f"  Aborted: {abort.reason}, "
            f"{abort.remaining} endpoint"
            f"{'s' if abort.remaining != 1 else ''} not tested",
            style="red bold",
        ))

    console.print(Panel(
        Group(*panel_parts),
        title=f"[bold]apisniff replay[/bold]  [dim]{domain}[/dim]",
        box=box.ROUNDED,
        expand=True,
        padding=(1, 1),
    ))

    summary_parts: list[tuple[str, str]] = []
    for cat in _CATEGORIES:
        n = counts.get(cat, 0)
        if n:
            summary_parts.append((
                f"{n} {cat.replace('_', ' ')}",
                _REPLAY_STYLE.get(cat, ""),
            ))
    console.print()
    summary = Text()
    for idx, (text, cat_style) in enumerate(summary_parts):
        if idx > 0:
            summary.append("  ·  ", style="dim")
        summary.append(text, style=f"bold {cat_style}")
    console.print(Align.center(summary))
    console.print()


def render_dry_run(
    safe: list[CapturedFlow],
    unsafe: list[CapturedFlow],
    domain: str,
    console: Console,
) -> None:
    console.print()

    table = Table(
        show_header=True, header_style="bold", expand=True,
        box=box.SIMPLE_HEAD, padding=(0, 1), show_edge=False,
    )
    table.add_column("Method", style="bold", min_width=6)
    table.add_column("Path", style="cyan", ratio=1)
    table.add_column("Captured", style="dim")
    table.add_column("Auth", style="dim")

    for flow in safe:
        ts = (
            datetime.fromtimestamp(flow.timestamp, tz=UTC).strftime("%Y-%m-%dT%H:%M")
            if flow.timestamp else "unknown"
        )
        table.add_row(flow.method.upper(), flow.path, ts, _auth_label(flow.request_headers))

    panel_parts: list[object] = [table]

    if unsafe:
        panel_parts.append(Text())
        panel_parts.append(Text(
            "  Skipped (unsafe, use --include-unsafe):", style="dim",
        ))
        for flow in unsafe:
            ts = (
                datetime.fromtimestamp(flow.timestamp, tz=UTC).strftime("%Y-%m-%dT%H:%M")
                if flow.timestamp else "unknown"
            )
            line = Text("  ")
            line.append(flow.method.upper(), style="dim bold")
            line.append(f"  {flow.path}", style="dim")
            line.append(f"  {ts}", style="dim")
            line.append(f"  {_auth_label(flow.request_headers)}", style="dim")
            panel_parts.append(line)

    console.print(Panel(
        Group(*panel_parts),
        title=f"[bold]apisniff replay[/bold] --dry-run  [dim]{domain}[/dim]",
        box=box.ROUNDED,
        expand=True,
        padding=(1, 1),
    ))

    console.print()
    summary = Text()
    summary.append(f"{len(safe)} safe", style="bold green")
    summary.append(
        f" endpoint{'s' if len(safe) != 1 else ''}",
        style="dim",
    )
    if unsafe:
        summary.append("  ·  ", style="dim")
        summary.append(f"{len(unsafe)} unsafe", style="bold red")
        summary.append(" skipped", style="dim")
    console.print(Align.center(summary))
    console.print()


def replay_to_json(
    results: list[ReplayResult],
    domain: str,
    abort: ReplayAbort | None = None,
) -> str:
    replayed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    counts = _tally_results(results)

    endpoints = []
    for r in results:
        endpoints.append({
            "method": r.original_flow.method,
            "path": r.original_flow.path,
            "original_status": r.original_flow.response_status,
            "replayed_status": r.replayed_status,
            "category": r.category,
            "body_shape_diff": r.body_shape_diff,
            "elapsed_ms": r.elapsed_ms,
        })

    data: dict = {
        "domain": domain,
        "replayed_at": replayed_at,
        "endpoints": endpoints,
        "summary": counts,
    }
    if abort:
        data["aborted"] = {
            "reason": abort.reason,
            "endpoints_not_tested": abort.remaining,
        }

    return json.dumps(data, indent=2)

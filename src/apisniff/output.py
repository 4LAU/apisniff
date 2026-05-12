from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import get_args

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apisniff.models import (
    CapturedFlow,
    ProbeAssessment,
    ProbeVerdict,
    RateLimitResult,
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

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Probe", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Time", justify="right")
    table.add_column("Result", justify="center")

    for probe_label in ("naked", "impersonated", "tls_only"):
        result = assessment.results[probe_label]
        if result.error:
            status_str = "error"
            result_str = Text("ERROR", style="red")
        elif result.is_challenge:
            status_str = str(result.status)
            result_str = Text("CHALLENGE", style="yellow")
        elif result.is_blocked:
            status_str = str(result.status)
            result_str = Text("BLOCKED", style="red")
        else:
            status_str = str(result.status)
            result_str = Text("PASS", style="green")

        table.add_row(
            probe_label,
            status_str,
            f"{result.elapsed_ms:.0f}ms",
            result_str,
        )

    console.print()
    console.print(
        Panel(
            table,
            title=f"[bold]apisniff probe[/bold] — {assessment.url}",
            subtitle=Text(label, style=style),
            expand=True,
        )
    )

    if assessment.vendors:
        vendor_table = Table(show_header=True, header_style="bold", expand=True)
        vendor_table.add_column("Vendor", style="cyan")
        vendor_table.add_column("Confidence", justify="center")
        vendor_table.add_column("Signals")

        for v in assessment.vendors:
            conf_style = {"high": "red", "medium": "yellow", "low": "dim"}.get(v.confidence, "")
            vendor_table.add_row(
                v.vendor.replace("_", " ").title(),
                Text(v.confidence.upper(), style=conf_style),
                ", ".join(v.signals),
            )

        console.print(Panel(vendor_table, title="Detected Vendors", expand=True))

    if assessment.graphql_endpoints:
        if assessment.graphql_introspection:
            gql_status = "[green]introspection enabled[/green]"
        else:
            gql_status = "[yellow]introspection disabled[/yellow]"
        for ep in assessment.graphql_endpoints:
            console.print(f"  GraphQL endpoint: [cyan]{ep}[/cyan] — {gql_status}")
        if assessment.graphql_schema_path:
            try:
                from pathlib import Path
                schema_data = json.loads(Path(assessment.graphql_schema_path).read_text())
                types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
                total_fields = sum(
                    len(t.get("fields", []) or []) for t in types
                )
                console.print(
                    f"  GraphQL schema: [bold]{len(types)}[/bold] types, "
                    f"[bold]{total_fields}[/bold] fields → {assessment.graphql_schema_path}"
                )
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                console.print(f"  GraphQL schema: {assessment.graphql_schema_path}")

    if assessment.rate_limit:
        rl = assessment.rate_limit
        console.print("  Rate Limit Probe:")
        if rl.first_block_at:
            console.print(f"    Blocked at request {rl.first_block_at} (HTTP {rl.block_status})")
            if rl.retry_after:
                console.print(f"    Retry-After: {rl.retry_after}s")
        elif rl.silent_throttle:
            console.print("    [yellow]Possible silent throttle[/yellow] (response times >2x in second half)")
        else:
            console.print(f"    No rate limiting observed in {rl.requests_sent} sequential requests")
        console.print(f"    Median response: {rl.median_ms:.0f}ms over {rl.requests_sent} requests")

    console.print()
    console.print(f"  [bold]Recommendation:[/bold] {assessment.recommendation}")
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

    for r in results:
        cat = r.category
        sym = _REPLAY_SYMBOL.get(cat, "?")
        style = _REPLAY_STYLE.get(cat, "")
        label = _CATEGORY_LABEL.get(cat, cat)

        orig_status = r.original_flow.response_status
        rep_status = r.replayed_status if r.replayed_status is not None else "err"
        method = r.original_flow.method.upper()
        path = r.original_flow.path

        line = (
            f"  {sym} {method:<4} {path:<30} "
            f"{orig_status}→{rep_status}  {label}  {r.elapsed_ms:.0f}ms"
        )
        console.print(Text(line, style=style))

        if cat == "drift" and r.body_shape_diff:
            for key, change in r.body_shape_diff.items():
                if isinstance(change, dict):
                    if change.get("was") is None:
                        console.print(Text(f"    + {key}", style="green"))
                    elif change.get("now") is None:
                        console.print(Text(f"    - {key}", style="red"))
                    else:
                        console.print(
                            Text(f"    ~ {key}", style="yellow")
                        )

    if abort:
        console.print()
        console.print(
            Text(
                f"  Aborted: {abort.reason} — "
                f"{abort.remaining} endpoint"
                f"{'s' if abort.remaining != 1 else ''} not tested",
                style="red bold",
            )
        )

    summary_parts = []
    for cat in _CATEGORIES:
        n = counts.get(cat, 0)
        if n:
            summary_parts.append(f"{n} {cat.replace('_', ' ')}")
    console.print()
    console.print(f"  Summary: {', '.join(summary_parts)}")


def render_dry_run(
    safe: list[CapturedFlow],
    unsafe: list[CapturedFlow],
    domain: str,
    console: Console,
) -> None:
    console.print()
    for flow in safe:
        ts = (
            datetime.fromtimestamp(flow.timestamp, tz=UTC).strftime("%Y-%m-%dT%H:%M")
            if flow.timestamp else "unknown"
        )
        auth = _auth_label(flow.request_headers)
        console.print(f"  {flow.method.upper():<6} {flow.path:<30} captured {ts}  auth:{auth}")

    if unsafe:
        console.print()
        console.print("  Skipped (unsafe — use --include-unsafe):")
        for flow in unsafe:
            ts = (
                datetime.fromtimestamp(flow.timestamp, tz=UTC).strftime("%Y-%m-%dT%H:%M")
                if flow.timestamp else "unknown"
            )
            auth = _auth_label(flow.request_headers)
            console.print(f"  {flow.method.upper():<6} {flow.path:<30} captured {ts}  auth:{auth}")

    console.print()
    console.print(
        f"  {len(safe)} safe endpoint{'s' if len(safe) != 1 else ''} would be replayed."
        f" {len(unsafe)} unsafe skipped."
    )


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

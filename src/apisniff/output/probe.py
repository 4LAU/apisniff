from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apisniff.models import ProbeAssessment, ProbeVerdict, get_header
from apisniff.output import (
    _VERDICT_ICONS,
    _VERDICT_STYLES,
    _error_label,
    _extract_set_cookie_names,
    _format_size,
    _latency_bar,
    _vendor_table,
)

_PROBE_HINTS = {
    "naked": "raw client, bot UA",
    "impersonated": "Chrome TLS + Chrome UA",
    "tls_only": "Chrome TLS, bot UA",
}

_PROBE_DESCRIPTIONS = {
    "naked": "Raw HTTP client, bot user-agent — tests baseline bot detection",
    "impersonated": (
        "Chrome TLS fingerprint + Chrome user-agent — tests if browser impersonation works"
    ),
    "tls_only": (
        "Chrome TLS fingerprint, bot user-agent — "
        "isolates whether detection is TLS-based or UA-based"
    ),
}

_VERDICT_DESCRIPTIONS = {
    "no_protection": "No active bot defenses detected — raw HTTP requests work",
    "client_dependent": (
        "Detection based on TLS fingerprint or user-agent — "
        "browser impersonation bypasses it"
    ),
    "js_challenge": "JavaScript challenge issued — requires a real browser session to solve",
    "full_block": "All automated access blocked — manual browser session required",
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
        "schema_version": 1,
        "url": assessment.url,
        "verdict": assessment.verdict.value,
        "interpretation": _build_probe_interpretation(assessment),
        "recommendation": assessment.recommendation,
        "probes": probes,
        "probe_descriptions": dict(_PROBE_DESCRIPTIONS),
        "verdict_descriptions": dict(_VERDICT_DESCRIPTIONS),
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


def _build_probe_interpretation(assessment: ProbeAssessment) -> str:
    target = _display_target(assessment.url)
    vendors = [_display_vendor(v.vendor) for v in assessment.vendors]
    vendor_text = _join_names(vendors)

    if assessment.verdict == ProbeVerdict.NO_PROTECTION:
        if vendor_text:
            return (
                f"{vendor_text} detected on {target} but not enforcing — "
                "raw HTTP requests work."
            )
        return f"No active defenses on {target} — raw HTTP requests work."

    if assessment.verdict == ProbeVerdict.JS_CHALLENGE:
        if vendor_text:
            return (
                f"{vendor_text} JS challenge on {target} — "
                "requires a real browser session."
            )
        return f"JavaScript challenge on {target} — requires a real browser session."

    if assessment.verdict == ProbeVerdict.FULL_BLOCK:
        if vendor_text:
            return (
                f"{vendor_text} blocks all automated access on {target} — "
                "manual browser session required."
            )
        return (
            f"{target} blocks all automated access — "
            "manual browser session required."
        )

    subject = f"{vendor_text} on {target}" if vendor_text else target
    naked = assessment.results.get("naked")
    impersonated = assessment.results.get("impersonated")
    tls_only = assessment.results.get("tls_only")

    if naked and impersonated and naked.is_blocked and not impersonated.is_blocked:
        if tls_only and tls_only.is_blocked:
            return (
                f"{subject} filters by TLS fingerprint and user-agent — "
                "browser impersonation required, raw clients blocked."
            )
        return (
            f"{subject} filters by TLS fingerprint — "
            "browser impersonation required, raw clients blocked."
        )

    if naked and impersonated and not naked.is_blocked and impersonated.is_blocked:
        if tls_only and tls_only.is_blocked:
            return (
                f"{subject} blocks impersonated browser TLS fingerprints — "
                "raw clients work, browser impersonation is blocked."
            )
        return (
            f"{subject} filters by browser user-agent — "
            "raw clients work, browser user-agent requests blocked."
        )

    if any(result.is_challenge for result in assessment.results.values()):
        return (
            f"{subject} challenges selectively by client signals — "
            "a real browser session may be required."
        )

    passed = [label for label, result in assessment.results.items() if not result.is_blocked]
    failed = [label for label, result in assessment.results.items() if result.is_blocked]
    if passed and failed:
        return (
            f"{subject} gives mixed probe results — "
            f"{_join_names(passed)} passed, {_join_names(failed)} blocked."
        )

    return (
        f"{subject} is client-dependent — "
        "browser-like request signals are likely required."
    )


def _display_target(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path or url


def _display_vendor(vendor: str) -> str:
    return vendor.replace("_", " ").title()


def _join_names(names: list[str]) -> str:
    if len(names) <= 1:
        return "".join(names)
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return f"{', '.join(names[:-1])}, and {names[-1]}"


def probe_to_json(assessment: ProbeAssessment) -> str:
    return json.dumps(probe_to_dict(assessment), indent=2)


def render_probe(assessment: ProbeAssessment, console: Console | None = None) -> None:
    console = console or Console(stderr=True)

    style, label = _VERDICT_STYLES[assessment.verdict]
    icon = _VERDICT_ICONS[assessment.verdict]

    if assessment.verdict == ProbeVerdict.NO_PROTECTION and assessment.vendors:
        label = "Passthrough"

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
    size_mismatch = max_body > 0 and any(s < max_body * 0.25 for s in body_sizes.values())

    table = Table(
        show_header=True,
        header_style="bold",
        expand=True,
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        show_edge=False,
    )
    table.add_column("Probe", style="cyan", min_width=14)
    table.add_column("", style="dim", ratio=1)
    table.add_column("Latency", min_width=24)
    table.add_column("Size", justify="right", min_width=7)
    table.add_column("Result", justify="center", min_width=14)

    for probe_name in ("naked", "impersonated", "tls_only"):
        result = assessment.results[probe_name]
        hint = _PROBE_HINTS.get(probe_name, "")
        latency = _latency_bar(result.elapsed_ms, max_ms)

        if result.error:
            err_label = _error_label(result.error)
            result_str = Text(f" {err_label} ", style="bold white on red")
            size_cell = Text("—", style="dim")
        elif result.is_challenge:
            result_str = Text(f" {result.status} CHALLENGE ", style="bold black on yellow")
            bsize = len(result.body) if result.body else 0
            size_cell = Text(_format_size(bsize), style="dim")
        else:
            bsize = len(result.body) if result.body else 0
            size_style = "red" if size_mismatch and bsize < max_body * 0.25 else "dim"
            if result.is_blocked:
                result_str = Text(f" {result.status} BLOCKED ", style="bold white on red")
            else:
                result_str = Text(f" {result.status} PASS ", style="bold black on bright_green")
            size_cell = Text(_format_size(bsize), style=size_style)

        table.add_row(probe_name, hint, latency, size_cell, result_str)

    panel_parts: list[object] = [table]

    vendor_table = _vendor_table(assessment.vendors)
    if vendor_table:
        panel_parts.append(Text())
        panel_parts.append(vendor_table)

    signal_lines: list[tuple[str, str | Text]] = []

    servers: list[str] = []
    vias: list[str] = []
    all_cookies: list[str] = []
    cors_per_probe: dict[str, str] = {}
    cache_vals: list[str] = []
    vary_items: list[str] = []
    content_types: dict[str, str] = {}
    first_cors_methods: str = ""

    for lbl, r in assessment.results.items():
        if r.error:
            continue
        h = r.headers

        s = get_header(h, "server")
        if s and s not in servers:
            servers.append(s)
        powered = get_header(h, "x-powered-by")
        if powered and powered not in servers:
            servers.append(powered)

        v = get_header(h, "via")
        if v and v not in vias:
            vias.append(v)

        for name in _extract_set_cookie_names(h):
            if name not in all_cookies:
                all_cookies.append(name)

        origin = get_header(h, "access-control-allow-origin")
        if origin:
            cors_per_probe[lbl] = origin
        if not first_cors_methods:
            methods = get_header(h, "access-control-allow-methods")
            if methods:
                first_cors_methods = methods

        cc = get_header(h, "cache-control")
        if cc and cc not in cache_vals:
            cache_vals.append(cc)
        vary = get_header(h, "vary")
        if vary:
            for item in vary.split(","):
                item = item.strip()
                if item and item not in vary_items:
                    vary_items.append(item)

        ct = get_header(h, "content-type")
        if ct:
            content_types[lbl] = ct.split(";")[0].strip()

    if servers:
        signal_lines.append(("Server", " · ".join(servers)))
    if vias:
        signal_lines.append(("Via", " · ".join(vias)))
    if all_cookies:
        signal_lines.append(("Cookies", " · ".join(all_cookies)))
    if cors_per_probe:
        unique_origins = set(cors_per_probe.values())
        if len(unique_origins) == 1:
            cors_text = f"Origin: {next(iter(unique_origins))}"
            if first_cors_methods:
                cors_text += f"    Methods: {first_cors_methods}"
            signal_lines.append(("CORS", cors_text))
        else:
            parts = [f"{lbl}: {orig}" for lbl, orig in cors_per_probe.items()]
            signal_lines.append(("CORS", "  ".join(parts)))
    if cache_vals or vary_items:
        parts = []
        if cache_vals:
            parts.append(" · ".join(cache_vals))
        if vary_items:
            parts.append(f"Vary: {', '.join(vary_items)}")
        signal_lines.append(("Cache", "    ".join(parts)))
    if len(set(content_types.values())) > 1:
        parts = [f"{lbl}: {ct}" for lbl, ct in content_types.items()]
        signal_lines.append(("Content", "  ".join(parts)))

    if signal_lines:
        panel_parts.append(Text())
        signal_table = Table(
            show_header=False,
            box=None,
            padding=(0, 1),
            show_edge=False,
        )
        signal_table.add_column("Label", style="dim", min_width=8)
        signal_table.add_column("Value")
        for sig_label, sig_value in signal_lines:
            signal_table.add_row(sig_label, sig_value)
        panel_parts.append(signal_table)

    console.print(
        Panel(
            Group(*panel_parts),
            title=f"[bold]apisniff probe[/bold]  [dim]{assessment.url}[/dim]",
            box=box.ROUNDED,
            expand=True,
            padding=(1, 1),
        )
    )

    if assessment.graphql_endpoints:
        if assessment.graphql_introspection:
            gql_status = "[green]introspection enabled[/green]"
        else:
            gql_status = "[yellow]introspection disabled[/yellow]"
        for ep in assessment.graphql_endpoints:
            console.print(f"  GraphQL  [cyan]{ep}[/cyan]  {gql_status}")
        if assessment.graphql_schema_path:
            try:
                schema_data = json.loads(Path(assessment.graphql_schema_path).read_text())
                types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
                total_fields = sum(len(t.get("fields", []) or []) for t in types)
                console.print(
                    f"  GraphQL  [bold]{len(types)}[/bold] types, "
                    f"[bold]{total_fields}[/bold] fields"
                )
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                pass

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

    console.print(
        Panel(
            Text(assessment.recommendation),
            border_style=style,
            box=box.ROUNDED,
            padding=(0, 1),
            expand=True,
        )
    )
    console.print()

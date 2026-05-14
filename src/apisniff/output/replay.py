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

from apisniff.models import CapturedFlow, ReplayAbort, ReplayCategory, ReplayResult

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
        counts[r.category] += 1
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
        show_header=True,
        header_style="bold",
        expand=True,
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        show_edge=False,
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
        panel_parts.append(
            Text(
                f"  Aborted: {abort.reason}, "
                f"{abort.remaining} endpoint"
                f"{'s' if abort.remaining != 1 else ''} not tested",
                style="red bold",
            )
        )

    console.print(
        Panel(
            Group(*panel_parts),
            title=f"[bold]apisniff replay[/bold]  [dim]{domain}[/dim]",
            box=box.ROUNDED,
            expand=True,
            padding=(1, 1),
        )
    )

    summary_parts: list[tuple[str, str]] = []
    for cat in _CATEGORIES:
        n = counts.get(cat, 0)
        if n:
            summary_parts.append((f"{n} {cat.replace('_', ' ')}", _REPLAY_STYLE.get(cat, "")))
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
        show_header=True,
        header_style="bold",
        expand=True,
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        show_edge=False,
    )
    table.add_column("Method", style="bold", min_width=6)
    table.add_column("Path", style="cyan", ratio=1)
    table.add_column("Captured", style="dim")
    table.add_column("Auth", style="dim")

    for flow in safe:
        ts = (
            datetime.fromtimestamp(flow.timestamp, tz=UTC).strftime("%Y-%m-%dT%H:%M")
            if flow.timestamp
            else "unknown"
        )
        table.add_row(flow.method.upper(), flow.path, ts, _auth_label(flow.request_headers))

    panel_parts: list[object] = [table]

    if unsafe:
        panel_parts.append(Text())
        panel_parts.append(Text("  Skipped (unsafe, use --include-unsafe):", style="dim"))
        for flow in unsafe:
            ts = (
                datetime.fromtimestamp(flow.timestamp, tz=UTC).strftime("%Y-%m-%dT%H:%M")
                if flow.timestamp
                else "unknown"
            )
            line = Text("  ")
            line.append(flow.method.upper(), style="dim bold")
            line.append(f"  {flow.path}", style="dim")
            line.append(f"  {ts}", style="dim")
            line.append(f"  {_auth_label(flow.request_headers)}", style="dim")
            panel_parts.append(line)

    console.print(
        Panel(
            Group(*panel_parts),
            title=f"[bold]apisniff replay[/bold] --dry-run  [dim]{domain}[/dim]",
            box=box.ROUNDED,
            expand=True,
            padding=(1, 1),
        )
    )

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
        endpoints.append(
            {
                "method": r.original_flow.method,
                "path": r.original_flow.path,
                "original_status": r.original_flow.response_status,
                "replayed_status": r.replayed_status,
                "category": r.category,
                "body_shape_diff": r.body_shape_diff,
                "elapsed_ms": r.elapsed_ms,
            }
        )

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

from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apisniff.auth import AuthPattern, ExtractedCookie
from apisniff.models import CapturedFlow, SessionStats, VendorMatch, normalize_path
from apisniff.output import _DROP_LABELS, _METHOD_STYLES, _vendor_table


def _format_duration(seconds: float) -> str:
    if seconds >= 3600:
        return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"
    if seconds >= 60:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{seconds:.0f}s"


def _session_stats_parts(
    session_stats: SessionStats | None,
    flows: list[CapturedFlow],
) -> list[object]:
    if not session_stats:
        return [Text(f"{len(flows)} flows", style="bold")]

    total = session_stats.total_flows
    kept = session_stats.kept_flows
    bar_width = 24
    kept_filled = (
        max(1, round((kept / total) * bar_width))
        if total > 0 and kept > 0
        else 0
    )

    session_line = Text()
    session_line.append(_format_duration(session_stats.duration_seconds), style="bold")
    session_line.append("  ", style="")
    session_line.append("█" * kept_filled, style="green")
    session_line.append("░" * (bar_width - kept_filled), style="bright_black")
    session_line.append(f"  {kept}", style="bold green")
    session_line.append(f"/{total} kept", style="dim")

    parts: list[object] = [session_line]
    if session_stats.dropped:
        drop_line = Text()
        items = sorted(session_stats.dropped.items(), key=lambda x: -x[1])
        for i, (cat, count) in enumerate(items):
            if i > 0:
                drop_line.append("  ·  ", style="dim")
            friendly = _DROP_LABELS.get(cat, cat)
            drop_line.append(f"{friendly} ", style="dim")
            drop_line.append(str(count), style="dim bold")
        parts.append(drop_line)
    return parts


def _auth_table(auth_patterns: list[AuthPattern]) -> Table | None:
    if not auth_patterns:
        return None

    auth_table = Table(
        show_header=True,
        header_style="bold",
        expand=True,
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        show_edge=False,
    )
    auth_table.add_column("Auth", style="cyan", min_width=16)
    auth_table.add_column("Detail", ratio=1, style="dim")
    auth_table.add_column("Flows", justify="right", min_width=5)
    for p in auth_patterns:
        auth_table.add_row(
            p.auth_type.replace("_", " "),
            p.detail,
            str(p.flow_count),
        )
    return auth_table


def _cookie_table(cookies: list[ExtractedCookie]) -> Table | None:
    if not cookies:
        return None

    by_domain: dict[str, list[ExtractedCookie]] = {}
    for c in cookies:
        by_domain.setdefault(c.domain, []).append(c)

    cookie_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        show_edge=False,
    )
    cookie_table.add_column("Domain")
    cookie_table.add_column("Names")

    for dom, clist in sorted(by_domain.items()):
        names = Text()
        for i, c in enumerate(clist):
            if i >= 8:
                names.append(f" +{len(clist) - 8} more", style="dim")
                break
            if i > 0:
                names.append(" · ", style="dim")
            names.append(c.name)
        secure_count = sum(1 for c in clist if c.secure)
        domain_cell = Text()
        domain_cell.append(dom)
        domain_cell.append(f" ({len(clist)})", style="dim")
        if secure_count:
            domain_cell.append(f"  {secure_count} secure", style="green")
        cookie_table.add_row(domain_cell, names)
    return cookie_table


def _endpoint_counts(flows: list[CapturedFlow]) -> Counter[str]:
    endpoint_counts: Counter[str] = Counter()
    for f in flows:
        key = f"{f.method.upper()} {normalize_path(f.path)}"
        endpoint_counts[key] += 1
    return endpoint_counts


def _endpoint_table(endpoint_counts: Counter[str]) -> Table | None:
    if not endpoint_counts:
        return None

    ep_table = Table(
        show_header=True,
        header_style="bold",
        expand=True,
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        show_edge=False,
    )
    ep_table.add_column("Method", min_width=7)
    ep_table.add_column("Endpoint", style="cyan", ratio=1)
    ep_table.add_column("Count", justify="right", min_width=5)

    shown = 0
    for ep, count in endpoint_counts.most_common(15):
        method, path = ep.split(" ", 1)
        mstyle = _METHOD_STYLES.get(method, "bold")
        ep_table.add_row(Text(method, style=mstyle), path, str(count))
        shown += 1

    remaining = len(endpoint_counts) - shown
    if remaining > 0:
        ep_table.add_row("", Text(f"… {remaining} more", style="dim"), "")

    return ep_table


def _append_optional_part(panel_parts: list[object], part: object | None) -> None:
    if part is None:
        return
    panel_parts.append(Text())
    panel_parts.append(part)


def _summary_text(
    flow_count: int,
    endpoint_count: int,
    auth_patterns: list[AuthPattern],
    cookies: list[ExtractedCookie],
) -> Text:
    summary = Text()
    summary.append(str(flow_count), style="bold")
    summary.append(" flows", style="dim")

    if endpoint_count:
        summary.append("  ·  ", style="dim")
        summary.append(str(endpoint_count), style="bold")
        summary.append(" endpoints", style="dim")

    if auth_patterns:
        summary.append("  ·  ", style="dim")
        summary.append(str(len(auth_patterns)), style="bold")
        summary.append(" auth types", style="dim")

    if cookies:
        summary.append("  ·  ", style="dim")
        summary.append(str(len(cookies)), style="bold")
        summary.append(" cookies", style="dim")

    return summary


def _paths_table(
    bundle_dir: Path,
    cookies_path: Path | None,
    graphql_schema_path: Path | None,
) -> Table:
    paths_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        show_edge=False,
    )
    paths_table.add_column("", style="dim", min_width=10)
    paths_table.add_column("")
    paths_table.add_row("Report", str(bundle_dir / "report.md"))
    if cookies_path:
        paths_table.add_row("Cookies", str(cookies_path))
    if graphql_schema_path:
        paths_table.add_row("GraphQL", str(graphql_schema_path))
    return paths_table


def render_recon(
    domain: str,
    session_stats: SessionStats | None,
    flows: list[CapturedFlow],
    vendors: list[VendorMatch],
    auth_patterns: list[AuthPattern],
    cookies: list[ExtractedCookie],
    bundle_dir: Path,
    cookies_path: Path | None = None,
    graphql_schema_path: Path | None = None,
    command: str = "recon",
    console: Console | None = None,
) -> None:
    console = console or Console(stderr=True)
    console.print()

    panel_parts = _session_stats_parts(session_stats, flows)
    _append_optional_part(panel_parts, _vendor_table(vendors))
    _append_optional_part(panel_parts, _auth_table(auth_patterns))
    _append_optional_part(panel_parts, _cookie_table(cookies))

    endpoint_counts = _endpoint_counts(flows)
    _append_optional_part(panel_parts, _endpoint_table(endpoint_counts))

    if graphql_schema_path:
        panel_parts.append(Text())
        panel_parts.append(Text("  GraphQL schema captured", style="green"))

    console.print(
        Panel(
            Group(*panel_parts),
            title=f"[bold]apisniff {command}[/bold]  [dim]{domain}[/dim]",
            box=box.ROUNDED,
            expand=True,
            padding=(1, 1),
        )
    )

    console.print()
    flow_count = session_stats.kept_flows if session_stats else len(flows)
    console.print(
        Align.center(
            _summary_text(flow_count, len(endpoint_counts), auth_patterns, cookies)
        )
    )
    console.print()

    console.print(_paths_table(bundle_dir, cookies_path, graphql_schema_path))

    if cookies_path:
        console.print(
            "  [yellow]cookies.txt contains session credentials"
            " — do not share or commit[/yellow]"
        )
    console.print()

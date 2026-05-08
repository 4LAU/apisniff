from __future__ import annotations

from collections import Counter

from apisniff.auth import AuthPattern, ExtractedCookie
from apisniff.models import CapturedFlow, SessionStats, VendorMatch
from apisniff.spec import normalize_path


def generate_report(
    domain: str,
    flows: list[CapturedFlow],
    session_stats: SessionStats | None,
    vendors: list[VendorMatch],
    auth_patterns: list[AuthPattern],
    cookies: list[ExtractedCookie],
) -> str:
    lines: list[str] = []

    lines.append(f"# {domain} — Recon Report")
    lines.append("")

    if session_stats:
        lines.append(f"**Started:** {session_stats.started_at}")
        lines.append(f"**Duration:** {session_stats.duration_seconds:.0f}s")
        lines.append("")

    # Flow statistics
    lines.append("## Flow Statistics")
    lines.append("")
    if session_stats:
        lines.append(f"- **Total flows:** {session_stats.total_flows}")
        lines.append(f"- **Kept:** {session_stats.kept_flows}")
        total_dropped = sum(session_stats.dropped.values())
        lines.append(f"- **Dropped:** {total_dropped}")
        for category, count in sorted(session_stats.dropped.items(), key=lambda x: -x[1]):
            lines.append(f"  - {category}: {count}")
    else:
        lines.append(f"- **Kept flows:** {len(flows)}")
        lines.append("- *Drop breakdown: session stats unavailable*")
    lines.append("")

    # Vendors
    if vendors:
        lines.append("## Detected Vendors")
        lines.append("")
        for v in vendors:
            name = v.vendor.replace("_", " ").title()
            signals = ", ".join(v.signals)
            lines.append(f"- **{name}** ({v.confidence}) — {signals}")
        lines.append("")

    # Auth
    if auth_patterns:
        lines.append("## Auth Patterns")
        lines.append("")
        lines.append("| Type | Detail | Flows |")
        lines.append("|---|---|---|")
        for p in auth_patterns:
            lines.append(f"| {p.auth_type} | {p.detail} | {p.flow_count} |")
        lines.append("")

    # Cookies
    if cookies:
        lines.append("## Cookies")
        lines.append("")
        by_domain: dict[str, list[ExtractedCookie]] = {}
        for c in cookies:
            by_domain.setdefault(c.domain, []).append(c)
        for dom, clist in sorted(by_domain.items()):
            lines.append(f"**{dom}** ({len(clist)} cookies)")
            for c in clist:
                lines.append(f"- `{c.name}` = `{c.value[:40]}{'...' if len(c.value) > 40 else ''}`")
        lines.append("")

    # Top endpoints
    if flows:
        lines.append("## Top API Endpoints")
        lines.append("")
        endpoint_counts: Counter[str] = Counter()
        for f in flows:
            key = f"{f.method} {normalize_path(f.path)}"
            endpoint_counts[key] += 1
        for ep, count in endpoint_counts.most_common(20):
            lines.append(f"- `{ep}` ({count})")
        lines.append("")

    return "\n".join(lines)

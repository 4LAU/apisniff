from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apisniff.auth import AuthPattern, ExtractedCookie
from apisniff.models import (
    COOKIE_ATTRS,
    CapturedFlow,
    ProbeAssessment,
    ProbeVerdict,
    ReplayAbort,
    ReplayCategory,
    ReplayResult,
    SessionStats,
    VendorMatch,
    get_header,
    normalize_path,
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

_DROP_LABELS: dict[str, str] = {
    "options": "preflight",
    "noise_domain": "other domains",
    "path_telemetry": "telemetry",
    "third_party": "third-party",
    "static_asset": "static",
    "same_site_noise": "site noise",
}

_METHOD_STYLES: dict[str, str] = {
    "GET": "bold green",
    "POST": "bold yellow",
    "PUT": "bold yellow",
    "PATCH": "bold yellow",
    "DELETE": "bold red",
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


def _extract_set_cookie_names(headers: dict[str, str]) -> list[str]:
    names: list[str] = []
    val = get_header(headers, "set-cookie")
    if not val:
        return names
    for part in val.replace("\n", ", ").split(", "):
        part = part.strip()
        if not part or "=" not in part:
            continue
        candidate = part.split("=", 1)[0].strip()
        if candidate.lower() in COOKIE_ATTRS:
            continue
        if ";" in candidate:
            candidate = candidate.rsplit(";", 1)[-1].strip()
            if not candidate or candidate.lower() in COOKIE_ATTRS:
                continue
        if candidate and candidate not in names:
            names.append(candidate)
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


def _vendor_table(vendors: list[VendorMatch]) -> Table | None:
    if not vendors:
        return None

    vendor_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        show_edge=False,
    )
    vendor_table.add_column("Name", style="cyan")
    vendor_table.add_column("Confidence")
    vendor_table.add_column("Signals", style="dim")
    for v in vendors:
        vendor_table.add_row(
            v.vendor.replace("_", " ").title(),
            _confidence_badge(v.confidence),
            ", ".join(v.signals),
        )
    return vendor_table


from apisniff.output.probe import probe_to_dict, probe_to_json, render_probe  # noqa: E402
from apisniff.output.recon import render_recon  # noqa: E402
from apisniff.output.replay import render_dry_run, render_replay, replay_to_json  # noqa: E402

__all__ = [
    "Align",
    "AuthPattern",
    "COOKIE_ATTRS",
    "CapturedFlow",
    "Console",
    "Counter",
    "ExtractedCookie",
    "Group",
    "Panel",
    "Path",
    "ProbeAssessment",
    "ProbeVerdict",
    "ReplayAbort",
    "ReplayCategory",
    "ReplayResult",
    "SessionStats",
    "Table",
    "Text",
    "UTC",
    "VendorMatch",
    "box",
    "datetime",
    "get_args",
    "get_header",
    "json",
    "normalize_path",
    "probe_to_dict",
    "probe_to_json",
    "render_dry_run",
    "render_probe",
    "render_recon",
    "render_replay",
    "replay_to_json",
]

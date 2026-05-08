from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apisniff.models import ProbeAssessment, ProbeVerdict

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

    return {
        "url": assessment.url,
        "verdict": assessment.verdict.value,
        "recommendation": assessment.recommendation,
        "probes": probes,
        "vendors": vendors,
        "graphql": {
            "endpoints": assessment.graphql_endpoints,
            "introspection": assessment.graphql_introspection,
        },
    }


def probe_to_json(assessment: ProbeAssessment) -> str:
    return json.dumps(probe_to_dict(assessment), indent=2)


def render_probe(assessment: ProbeAssessment, console: Console | None = None) -> None:
    console = console or Console()

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

    console.print()
    console.print(f"  [bold]Recommendation:[/bold] {assessment.recommendation}")
    console.print()

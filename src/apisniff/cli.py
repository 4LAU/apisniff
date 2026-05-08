# src/apisniff/cli.py
from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console

app = typer.Typer(
    name="apisniff",
    help="One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.",
    no_args_is_help=True,
)

stderr = Console(stderr=True)

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_BLOCKED = 2


@app.command()
def probe(
    url: str = typer.Argument(help="URL to probe (e.g. redfin.com)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    proxy: str | None = typer.Option(
        None, "--proxy", help="Route probes through proxy (SOCKS5/HTTP)"
    ),
    header: list[str] | None = typer.Option(
        None, "--header", "-H", help="Extra header (key:value)"
    ),
    cookie: str | None = typer.Option(None, "--cookie", help="Cookie header value"),
    skip_graphql: bool = typer.Option(
        False, "--skip-graphql", help="Skip GraphQL endpoint detection"
    ),
) -> None:
    """Defense preflight -- what kind of surface am I dealing with?"""
    from apisniff.models import ProbeVerdict
    from apisniff.output import probe_to_json, render_probe
    from apisniff.probe import run_probes

    extra_headers: dict[str, str] = {}
    if header:
        for h in header:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()
    if cookie:
        extra_headers["cookie"] = cookie

    assessment = asyncio.run(
        run_probes(
            url,
            headers=extra_headers or None,
            proxy=proxy,
            skip_graphql=skip_graphql,
        )
    )

    if json_output:
        sys.stdout.write(probe_to_json(assessment) + "\n")
    else:
        render_probe(assessment, stderr)

    if assessment.verdict == ProbeVerdict.FULL_BLOCK:
        raise SystemExit(_EXIT_BLOCKED)


@app.command()
def recon(
    domain: str = typer.Argument(help="Domain to capture traffic from"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    proxy: str | None = typer.Option(None, "--proxy", help="Upstream proxy for mitmproxy"),
    port: int = typer.Option(8080, "--port", help="Local proxy port"),
) -> None:
    """Capture + classify -- browse a site through the proxy, classify everything."""
    from apisniff.recon import run_recon

    run_recon(domain, port=port, proxy=proxy, json_output=json_output)


@app.command()
def spec(
    domain: str = typer.Argument(help="Domain to generate spec for"),
    input_file: str | None = typer.Option(
        None, "--input", "-i", help="Input file (JSONL, HAR, or mitmproxy flow)"
    ),
    output_format: str = typer.Option("yaml", "--format", "-f", help="Output format: yaml or json"),
    output_file: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    infer_schemes: bool = typer.Option(
        False, "--infer-security-schemes",
        help="Promote observed auth patterns to components.securitySchemes (default: extensions only)",
    ),
) -> None:
    """Extract API structure -- generate OpenAPI from captured traffic."""
    from apisniff.spec import run_spec

    run_spec(domain, input_file=input_file, output_format=output_format, output_file=output_file, infer_schemes=infer_schemes)

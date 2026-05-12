# src/apisniff/cli.py
from __future__ import annotations

import asyncio
import os
import sys

import click
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


def _parse_header_args(header: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if header:
        for h in header:
            k, sep, v = h.partition(":")
            if not sep:
                raise typer.BadParameter(f"Invalid header (missing ':'): {h}")
            result[k.strip()] = v.strip()
    return result


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
    impersonate: str = typer.Option(
        "chrome", "--impersonate",
        help="TLS profile: chrome, chrome131, chrome120, safari17_0, firefox133",
    ),
    probe_rate: bool = typer.Option(
        False, "--probe-rate", help="Send 20 requests to detect rate limiting (opt-in)",
    ),
) -> None:
    """Defense preflight -- what kind of surface am I dealing with?"""
    from apisniff.models import ProbeVerdict
    from apisniff.output import probe_to_json, render_probe
    from apisniff.probe import run_probes

    extra_headers = _parse_header_args(header)
    if cookie:
        extra_headers["cookie"] = cookie

    assessment = asyncio.run(
        run_probes(
            url,
            headers=extra_headers or None,
            proxy=proxy,
            skip_graphql=skip_graphql,
            impersonate=impersonate,
            probe_rate=probe_rate,
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
def analyze(
    input_file: str = typer.Argument(..., help="Input file (HAR, Burp XML, or JSONL)"),
    domain: str | None = typer.Option(
        None, "--domain", "-d", help="Target domain (auto-detected if omitted)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output session stats as JSON"),
    output_dir: str | None = typer.Option(
        None, "--output-dir", help="Directory to write bundle (default: ~/apisniff-captures/)"
    ),
    fetch_graphql: bool = typer.Option(
        False, "--fetch-graphql", help="Fetch GraphQL schema from detected endpoints"
    ),
) -> None:
    """Offline analysis -- import traffic capture, classify, extract everything."""
    if not os.path.isfile(input_file):
        stderr.print(f"[red]File not found: {input_file}[/red]")
        raise SystemExit(_EXIT_ERROR)

    from apisniff.recon import run_analyze

    run_analyze(
        input_file,
        domain=domain,
        json_output=json_output,
        output_dir=output_dir,
        fetch_graphql=fetch_graphql,
    )


@app.command()
def replay(
    bundle: str = typer.Argument(help="Bundle directory path or domain name"),
    filter_pattern: str | None = typer.Option(None, "--filter", help="Glob filter for paths"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    cookie_file: str | None = typer.Option(None, "--cookie-file", help="Netscape cookies.txt path"),
    header: list[str] | None = typer.Option(
        None, "--header", "-H", help="Extra header (key:value)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    output_file: str | None = typer.Option(
        None, "--output", "-o", help="Write JSON output to file"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="List endpoints without replaying"),
    include_unsafe: bool = typer.Option(
        False, "--include-unsafe", help="Include non-GET/HEAD/OPTIONS methods"
    ),
    insecure: bool = typer.Option(False, "--insecure", help="Skip TLS verification"),
    impersonate: str = typer.Option(
        "chrome", "--impersonate",
        help="TLS profile: chrome, chrome131, chrome120, safari17_0, firefox133",
    ),
) -> None:
    """Replay captured API calls and detect drift."""
    from apisniff.replay import run_replay

    extra_headers = _parse_header_args(header)

    kwargs: dict = dict(
        filter_=filter_pattern,
        timeout=timeout,
        cookie_file=cookie_file,
        extra_headers=extra_headers or None,
        include_unsafe=include_unsafe,
        insecure=insecure,
        dry_run=dry_run,
        json_output=json_output,
        output_file=output_file,
        impersonate=impersonate,
    )
    if os.path.isdir(bundle):
        kwargs["bundle_dir"] = bundle
    else:
        kwargs["domain"] = bundle

    try:
        asyncio.run(run_replay(**kwargs))
    except FileNotFoundError as e:
        stderr.print(f"[red]{e}[/red]")
        raise SystemExit(_EXIT_ERROR)


@app.command()
def spec(
    domain: str = typer.Argument(help="Domain to generate spec for"),
    input_file: str | None = typer.Option(
        None, "--input", "-i", help="Input file (JSONL, HAR, or mitmproxy flow)"
    ),
    output_format: str = typer.Option(
        "yaml", "--format", "-f", help="Output format: yaml or json",
        click_type=click.Choice(["yaml", "json"]),
    ),
    output_file: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    infer_schemes: bool = typer.Option(
        False, "--infer-security-schemes",
        help="Promote observed auth to securitySchemes (default: extensions only)",
    ),
    include_examples: bool = typer.Option(
        False, "--examples", help="Include sample response values in generated spec",
    ),
) -> None:
    """Extract API structure -- generate OpenAPI from captured traffic."""
    from apisniff.spec import run_spec

    run_spec(
        domain, input_file=input_file, output_format=output_format,
        output_file=output_file, infer_schemes=infer_schemes,
        include_examples=include_examples,
    )


@app.command()
def share(
    bundle: str = typer.Argument(help="Bundle directory path or domain name"),
    output: str | None = typer.Option(
        None, "--output", "-o",
        help="Output directory (default: <bundle>-shared)",
    ),
    domain: str | None = typer.Option(
        None, "--domain", "-d",
        help="Domain (auto-detected from session.json if omitted)",
    ),
) -> None:
    """Export a shareable summary — no raw traffic, no credentials."""
    from apisniff.share import share_bundle

    if os.path.isdir(bundle):
        src = bundle
    else:
        from apisniff.bundle import find_latest_bundle
        found = find_latest_bundle(bundle)
        if found is None:
            stderr.print(
                f"[red]No captures found for {bundle}.[/red]"
            )
            raise SystemExit(_EXIT_ERROR)
        src = str(found)

    if domain is None:
        import json
        session_path = os.path.join(src, "session.json")
        try:
            with open(session_path) as f:
                domain = json.load(f).get("domain")
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
        if domain is None:
            stderr.print(
                "[red]Cannot detect domain — use --domain.[/red]"
            )
            raise SystemExit(_EXIT_ERROR)

    dst = output or f"{src}-shared"
    if os.path.exists(dst):
        stderr.print(f"[red]Output directory already exists: {dst}[/red]")
        raise SystemExit(_EXIT_ERROR)

    stats = share_bundle(src, dst, domain)
    stderr.print(f"  Shared {stats['flows_processed']} flows as derived artifacts → {dst}")
    stderr.print(f"  {stats['paths']} paths, {stats['endpoints']} endpoints")
    stderr.print("  Contains: spec.yaml, inventory.json, session.json, report.md")
    stderr.print("  No raw traffic or credentials included.")

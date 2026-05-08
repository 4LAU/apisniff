import typer

app = typer.Typer(
    name="apisniff",
    help="One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.",
    no_args_is_help=True,
)


@app.command()
def probe(url: str) -> None:
    """Defense preflight -- what kind of surface am I dealing with?"""
    typer.echo(f"probe: {url} (not yet implemented)")


@app.command()
def recon(domain: str) -> None:
    """Capture + classify -- browse a site through the proxy, classify everything."""
    typer.echo(f"recon: {domain} (not yet implemented)")


@app.command()
def spec(domain: str) -> None:
    """Extract API structure -- generate OpenAPI from captured traffic."""
    typer.echo(f"spec: {domain} (not yet implemented)")

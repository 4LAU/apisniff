# apisniff

One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.

[![CI](https://github.com/4LAU/apisniff/actions/workflows/ci.yml/badge.svg)](https://github.com/4LAU/apisniff/actions)
[![PyPI](https://img.shields.io/pypi/v/apisniff)](https://pypi.org/project/apisniff/)
[![Python](https://img.shields.io/pypi/pyversions/apisniff)](https://pypi.org/project/apisniff/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What you get

- Probe a URL in 10 seconds, classify 25+ vendor products (Cloudflare, Akamai, DataDome, PerimeterX, Imperva, Kasada, and more)
- Browse a site through a local [mitmproxy](https://github.com/mitmproxy/mitmproxy) instance. Raw non-OPTIONS traffic is preserved locally, then projected into a clean API spec and categorized surface inventory.
- Import HAR files or Burp Suite exports for offline analysis
- Generate a clean OpenAPI spec from captured traffic with schema inference, auth detection, and opt-in broader views for third-party or challenge traffic
- Replay captured calls against the live API and see what changed
- Export safely: derived artifacts only, no raw traffic, no credentials

## Install

```bash
brew tap 4LAU/tap && brew install apisniff
# or
pip install apisniff
# or
pipx install apisniff
# or
uv tool install apisniff
```

Requires Python 3.12+.

## Quick Start

```bash
# Check what defenses a site has
apisniff probe example.com

# Capture live traffic (opens Chrome + proxy)
apisniff recon example.com

# Generate an API spec from the capture
apisniff spec example.com -o spec.yaml

# Replay captured calls to detect drift
apisniff replay example.com

# Export a safe, shareable summary
apisniff share example.com
```

## Commands

| Command | Purpose | Docs |
|---------|---------|------|
| [`probe`](docs/commands/probe.md) | Defense preflight: assess defenses, detect vendors, check rate limits | [Reference →](docs/commands/probe.md) |
| [`recon`](docs/commands/recon.md) | Capture + classify: browse through proxy, preserve traffic, generate report | [Reference →](docs/commands/recon.md) |
| [`analyze`](docs/commands/analyze.md) | Offline analysis: import HAR, Burp XML, or JSONL captures | [Reference →](docs/commands/analyze.md) |
| [`replay`](docs/commands/replay.md) | Replay captured calls and detect API drift | [Reference →](docs/commands/replay.md) |
| [`spec`](docs/commands/spec.md) | Generate OpenAPI 3.0.3 from captured traffic | [Reference →](docs/commands/spec.md) |
| [`share`](docs/commands/share.md) | Export shareable summary (no raw traffic, no credentials) | [Reference →](docs/commands/share.md) |

Every command supports `--help` for full flag documentation. See the [CLI spec](docs/spec.md) for output format contracts and conventions.

## Guides

- [Getting started](docs/guides/getting-started.md): install to API map in 5 minutes
- [Workflow recipes](docs/guides/workflows.md): map an API, check for drift, compare defenses
- [Capture formats](docs/guides/capture-formats.md): HAR, Burp XML, JSONL explained

## Important Warnings

Only run apisniff against systems you own, administer, or have explicit permission to test. The tool is built for API discovery and debugging, but it sends real requests and can capture sensitive session data.

### Your IP address is exposed

**This tool sends real HTTP requests from your IP.** Aggressive or repeated probing can get you rate-limited or blocked. `apisniff probe rate` fires 20 rapid requests, so use it deliberately. Route through `--proxy` if you don't want to expose your IP.

Results reflect your IP's reputation. Residential IPs see fewer challenges than datacenter/cloud IPs. Use `--proxy` to compare results from different vantage points.

### Capture files contain sensitive data

`recon` and `analyze` capture **full HTTP traffic** including cookies, auth tokens, API keys, and form submissions. Raw bundles are stored locally with owner-only permissions and are **never safe to share, commit, or upload**.

Use `apisniff share` to create a safe export with only derived artifacts.

### Why recon needs the mitmproxy certificate

`apisniff recon` uses [mitmproxy](https://github.com/mitmproxy/mitmproxy), an open source SSL/TLS-capable intercepting proxy for HTTP/1, HTTP/2, and WebSockets. mitmproxy is built for the same authorized inspection work penetration testers and software developers already do when they need to see what an app is sending over HTTPS. apisniff starts it locally, opens Chrome with that local proxy configured, then records the HTTP flows that pass through it.

HTTPS is encrypted between the browser and the origin server, so a proxy cannot read request paths, JSON bodies, headers, or responses unless the browser trusts the proxy during the TLS handshake. mitmproxy solves this by creating a local certificate authority the first time it runs, stored under `~/.mitmproxy`, and generating site certificates on the fly for the domains you visit. Installing or trusting that CA certificate tells the browser: "for this local capture session, allow this proxy to inspect HTTPS traffic."

Treat the certificate like sensitive local configuration. A trusted CA can decrypt HTTPS traffic from clients that trust it and send traffic through the proxy, so only install the mitmproxy CA on machines and browser profiles you control. apisniff uses a local proxy on `127.0.0.1` and launches Chrome with `--proxy-server=http://127.0.0.1:8080`; regular browsing and apps are unaffected unless you route them through that proxy. If Chrome shows certificate warnings, start `apisniff recon`, open `http://mitm.it` in the proxied Chrome window, and follow mitmproxy's platform-specific certificate instructions.

### What recon can see

`apisniff recon` only records traffic from clients that are explicitly sent through its local proxy. By default, that means the Chrome window apisniff launches with `--proxy-server=http://127.0.0.1:8080`.

Other apps, other browser windows, background services, and normal device traffic are not routed through apisniff unless you configure them to use that same local proxy. apisniff does not turn on device-wide network capture, install a VPN, or monitor traffic outside the local proxy session.

By default, `recon` starts mitmproxy on local port `8080`; use `--port` to choose a different port. Press **Ctrl+C** to end the session. apisniff sends SIGINT to both mitmproxy and the Chrome instance it launched, then releases the local proxy port. If you see a port-in-use error, a previous `recon` session is probably still running.

More detail: [mitmproxy certificate docs](https://docs.mitmproxy.org/stable/concepts/certificates/) and [how mitmproxy works](https://docs.mitmproxy.org/stable/concepts/how-mitmproxy-works/). For questions about mitmproxy itself, see the [mitmproxy GitHub repository](https://github.com/mitmproxy/mitmproxy).

## What to do with the spec

```bash
# Generate a client library
openapi-generator generate -i spec.yaml -g python -o client/

# Import into Postman: File → Import → select spec.yaml

# Feed to an LLM
cat spec.yaml | llm "write a Python client for this API"
```

## Development

```bash
git clone https://github.com/4LAU/apisniff.git
cd apisniff
uv sync --dev
uv run pytest tests/ -v
uv run ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the local development workflow and [SECURITY.md](SECURITY.md) for vulnerability reporting.

To regenerate command reference docs after changing CLI flags:

```bash
uv run python scripts/generate_command_docs.py
```

## License

MIT

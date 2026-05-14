# apisniff

One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.

[![CI](https://github.com/4LAU/apisniff/actions/workflows/ci.yml/badge.svg)](https://github.com/4LAU/apisniff/actions)
[![PyPI](https://img.shields.io/pypi/v/apisniff)](https://pypi.org/project/apisniff/)
[![Python](https://img.shields.io/pypi/pyversions/apisniff)](https://pypi.org/project/apisniff/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What you get

- Probe a URL in 10 seconds, classify 25+ vendor products (Cloudflare, Akamai, DataDome, PerimeterX, Imperva, Kasada, and more)
- Browse a site through a local proxy. Noise is filtered automatically; you keep only API calls.
- Import HAR files or Burp Suite exports for offline analysis
- Generate an OpenAPI spec from captured traffic with schema inference and example values
- Replay captured calls against the live API and see what changed
- Export safely: derived artifacts only, no raw traffic, no credentials

## Install

```bash
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
| [`recon`](docs/commands/recon.md) | Capture + classify: browse through proxy, filter noise, generate report | [Reference →](docs/commands/recon.md) |
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

### Your IP address is exposed

**This tool sends real HTTP requests from your IP.** Aggressive or repeated probing can get you rate-limited or blocked. `apisniff probe rate` fires 20 rapid requests, so use it deliberately. Route through `--proxy` if you don't want to expose your IP.

Results reflect your IP's reputation. Residential IPs see fewer challenges than datacenter/cloud IPs. Use `--proxy` to compare results from different vantage points.

### Capture files contain sensitive data

`recon` and `analyze` capture **full HTTP traffic** including cookies, auth tokens, API keys, and form submissions. Raw bundles are stored locally with owner-only permissions and are **never safe to share, commit, or upload**.

Use `apisniff share` to create a safe export with only derived artifacts.

### About the mitmproxy certificate

`recon` requires trusting mitmproxy's CA certificate (one-time macOS Keychain setup). The proxy runs locally on `127.0.0.1`; only traffic explicitly routed through port 8080 is intercepted. Regular browsing and apps are unaffected.

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

To regenerate command reference docs after changing CLI flags:

```bash
uv run python scripts/generate_command_docs.py
```

## License

MIT

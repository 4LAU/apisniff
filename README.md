# apisniff

One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.

[![CI](https://github.com/4LAU/apisniff/actions/workflows/ci.yml/badge.svg)](https://github.com/4LAU/apisniff/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What you get

- Probe a URL in 10 seconds, classify 25+ vendor products (Cloudflare, Akamai, DataDome, PerimeterX, Imperva, Kasada, and more)
- Capture by default through a clean Chrome (no automation fingerprint) routed through a local MITM proxy — log in past bot detection (DataDome, PerimeterX, and similar) and record real on-the-wire cookies that make captures replayable; opt into CDP modes (`--mode cdp-launch` / `cdp-attach`) for WebSocket-frame capture or attaching to an existing browser
- Import HAR files or Burp Suite exports for offline analysis
- Generate an OpenAPI spec from captured traffic with schema inference and example values
- Replay captured calls against the live API and see what changed
- Export safely: derived artifacts only, no raw traffic, no credentials

## Install

```bash
brew tap 4LAU/tap && brew install apisniff
```

The Go build is a single binary with no Python runtime dependency. From source:

```bash
go build -ldflags="-s -w" -o apisniff ./cmd/apisniff
```

## Quick Start

```bash
# Check what defenses a site has
apisniff probe example.com

# Capture real traffic: opens a clean Chrome (no automation fingerprint) routed
# through a local MITM proxy. Log in by hand, then close the window (or Ctrl+C)
# to finish. Records real on-the-wire cookies on XHR/fetch, so captures replay.
apisniff recon example.com

# CDP mode: capture WebSocket frames or attach to an existing browser.
# Does not capture Cookie/Set-Cookie on XHR/fetch.
apisniff recon example.com --mode cdp-launch

# Run only the proxy (no browser) — point your own client at 127.0.0.1:8080
apisniff recon example.com --no-browser --port 8080

# Generate an API spec from the capture
apisniff spec example.com -o spec.yaml

# Replay captured calls to detect drift
apisniff replay example.com

# List local capture bundles
apisniff bundles

# Remove old capture bundles after review
apisniff clean --older-than 30d --dry-run
apisniff clean --older-than 30d --yes

# Export a safe, shareable summary
apisniff share example.com
```

## Commands

| Command | Purpose | Docs |
|---------|---------|------|
| [`probe`](docs/commands/probe.md) | Defense preflight: assess defenses, detect vendors, check rate limits | [Reference →](docs/commands/probe.md) |
| [`recon`](docs/commands/recon.md) | Capture + classify: clean-Chrome proxy by default (real cookies), CDP modes for WebSocket frames, filter noise | [Reference →](docs/commands/recon.md) |
| [`analyze`](docs/commands/analyze.md) | Offline analysis: import HAR, Burp XML, or JSONL captures | [Reference →](docs/commands/analyze.md) |
| [`replay`](docs/commands/replay.md) | Replay captured calls and detect API drift | [Reference →](docs/commands/replay.md) |
| [`spec`](docs/commands/spec.md) | Generate OpenAPI 3.0.3 from captured traffic | [Reference →](docs/commands/spec.md) |
| [`share`](docs/commands/share.md) | Export shareable summary (no raw traffic, no credentials) | [Reference →](docs/commands/share.md) |
| `bundles` | List local capture bundles; add `--credentials` to opt into credential detection and `--json` for machine output | `apisniff bundles --help` |
| `clean` | Explicitly delete local capture bundles with `--older-than`, `--domain`, `--all`, `--yes`, `--dry-run`, and `--json` | `apisniff clean --help` |

Every command supports `--help` for full flag documentation. See the [CLI spec](docs/spec.md) for output format contracts and conventions.

## Guides

- [Getting started](docs/guides/getting-started.md): install to API map in 5 minutes
- [Workflow recipes](docs/guides/workflows.md): map an API, check for drift, compare defenses
- [Capture formats](docs/guides/capture-formats.md): HAR, Burp XML, JSONL explained

## Important Warnings

Only run apisniff against systems you own, administer, or have explicit permission to test. The tool is built for API discovery and debugging, but it sends real requests and can capture sensitive session data.

### Your IP address is exposed

**This tool sends real HTTP requests from your IP.** Aggressive or repeated probing can get you rate-limited or blocked. `apisniff probe rate` fires rapid requests, so use it deliberately.

Results reflect your IP's reputation. Residential IPs see fewer challenges than datacenter/cloud IPs. Use `--proxy` to compare results from different vantage points.

### Capture files contain sensitive data

`recon` and `analyze` capture **full HTTP traffic** including cookies, auth tokens, API keys, and form submissions. Raw bundles are stored locally with owner-only permissions and are **never safe to share, commit, or upload**.

Raw capture bundles persist until you explicitly remove them. Use `apisniff bundles` for a metadata-only inventory, `apisniff bundles --credentials` when you intentionally want local credential detection, and `apisniff clean --dry-run` before deleting bundles with `apisniff clean --yes`. `clean` is explicit and does not auto-delete captures.

Use `apisniff share` to create a safe export with only derived artifacts.

### Recon capture modes

`apisniff recon` defaults to proxy mode. It starts a local HTTP/HTTPS MITM proxy with HTTP/2 support and launches a real Chrome routed through it. That Chrome carries **no automation fingerprint** — no `--enable-automation`, no DevTools/CDP attachment, so `navigator.webdriver` is false — which is what lets you log in past bot-detection vendors (DataDome, PerimeterX, and similar) that block CDP-launched browsers. Because the proxy sees the wire, it captures the **real Cookie/Set-Cookie headers on XHR/fetch**, so authenticated captures are replayable. Chrome runs a fresh, disposable profile (wiped on exit, separate from your everyday Chrome), so you log in by hand each session. Log in, exercise the parts of the app you want captured, then **close the browser window** (or press Ctrl+C) to finish.

For HTTPS, the launched Chrome accepts the proxy's certificates via `--ignore-certificate-errors-spki-list` — the CA's public-key hash is passed on the command line, so **nothing is installed in any OS trust store and there is no keychain prompt**. Chrome shows a cosmetic "unsupported command-line flag" warning bar; that is browser UI only and is invisible to pages. The CA private key at `~/.apisniff/ca-key.pem` is sensitive (anything holding it can forge HTTPS certs for clients that trust the CA); it is stored with owner-only permissions.

Pass `--no-browser` to start only the proxy and route your own client through `127.0.0.1:<port>` instead; in that case trust `~/.apisniff/ca-cert.pem` in that client yourself.

`--mode cdp-launch` is the only mode that captures WebSocket frames, plus `resource_type` and cache/service-worker/body-size metadata, from Chrome's Network domain. It launches Chrome with a dedicated user data directory and a DevTools port. It does **not** capture Cookie/Set-Cookie on XHR/fetch (those are not exposed over CDP), so authenticated captures from CDP modes are not replayable the same way proxy captures are.

`--mode cdp-attach` connects to an existing Chrome DevTools endpoint with `--remote-url` or `--port` and has the same capture capabilities — and the same cookie limitation — as `cdp-launch`.

### What recon can see

CDP modes only record traffic from the Chrome session apisniff launches or attaches to. Proxy mode only records traffic from clients explicitly configured to use the local proxy.

Other apps, other browser windows, background services, and normal device traffic are not routed through apisniff unless you configure them for the same capture mode. apisniff does not turn on device-wide network capture, install a VPN, or monitor traffic outside the chosen session.

To end a proxy capture session, close the launched Chrome's last window/tab or press **Ctrl+C** in the terminal; either one saves the bundle. (apisniff notices the window closing by watching the launched browser's own processes — no automation hook on the page.) If you see a port-in-use error, another capture session is probably still running on that port.

When passive recon finds capture bundles older than 30 days, apisniff warns so you can review and clean them deliberately.

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
go test ./...
go build -o apisniff ./cmd/apisniff
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the local development workflow and [SECURITY.md](SECURITY.md) for vulnerability reporting.

Build release binaries with `-ldflags="-s -w"` to keep binary size under the distribution target.

## License

MIT

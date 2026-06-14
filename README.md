# apisniff

One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.

[![CI](https://github.com/4LAU/apisniff/actions/workflows/ci.yml/badge.svg)](https://github.com/4LAU/apisniff/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What you get

- Probe a URL in 10 seconds, classify 25+ vendor products (Cloudflare, Akamai, DataDome, PerimeterX, Imperva, Kasada, and more)
- Capture browser traffic through Chrome DevTools Protocol by default, or use proxy mode to drive a clean Chrome with no automation fingerprint — enough to log in past bot detection (DataDome, PerimeterX, and similar)
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

# Capture live traffic with Chrome DevTools Protocol
apisniff recon example.com

# Proxy mode: opens a clean Chrome routed through a MITM proxy. Log in by
# hand (no automation fingerprint), then close the window (or Ctrl+C) to finish.
apisniff recon example.com --mode proxy

# Proxy mode without launching a browser — point your own client at it
apisniff recon example.com --mode proxy --no-browser --port 8080

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
| [`recon`](docs/commands/recon.md) | Capture + classify: CDP by default, proxy fallback, filter noise | [Reference →](docs/commands/recon.md) |
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

`apisniff recon` defaults to `--mode cdp-launch`. It launches Chrome with a dedicated user data directory and a DevTools port, then captures request/response data from Chrome's Network domain. The target sees Chrome's real TLS and HTTP/2 behavior, but JavaScript-level automation signals may still exist because Chrome is launched for automation.

`--mode cdp-attach` connects to an existing Chrome DevTools endpoint with `--remote-url` or `--port`.

CDP capture records API responses, response body size metadata, and WebSocket handshake/frame summaries when Chrome exposes those events.

`--mode proxy` starts a local HTTP/HTTPS MITM proxy with HTTP/2 support and, by default, launches a real Chrome routed through it. That Chrome carries **no automation fingerprint** — no `--enable-automation`, no DevTools/CDP attachment, so `navigator.webdriver` is false — which is what lets you log in past bot-detection vendors that block CDP-launched browsers. It uses a fresh, disposable profile (wiped on exit, separate from your everyday Chrome), so you log in by hand each session. Log in, exercise the parts of the app you want captured, then **close the browser window** (or press Ctrl+C) to finish.

For HTTPS capture the browser must trust the proxy's certificate authority (`~/.apisniff/ca-cert.pem`). On macOS, proxy mode trusts it automatically in your login keychain the first time (a one-time approval prompt, no admin) so there is no browser warning. Treat that CA as sensitive: a trusted CA can decrypt HTTPS traffic from clients that trust it. The private key is stored at `~/.apisniff/ca-key.pem` with owner-only permissions. Remove the trust anytime with `security delete-certificate -c "apisniff local MITM CA"`.

Pass `--no-browser` to start only the proxy and route your own client through `127.0.0.1:<port>` instead; in that case trust the CA in that client yourself.

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

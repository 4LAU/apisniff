# apisniff

One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.

[![CI](https://github.com/aaronlau/apisniff/actions/workflows/ci.yml/badge.svg)](https://github.com/aaronlau/apisniff/actions)
[![PyPI](https://img.shields.io/pypi/v/apisniff)](https://pypi.org/project/apisniff/)
[![Python](https://img.shields.io/pypi/pyversions/apisniff)](https://pypi.org/project/apisniff/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Install

```bash
pip install apisniff
# or
pipx install apisniff
```

## Commands

### `probe` — Defense preflight

What kind of surface am I dealing with? 10 seconds, zero configuration.

```bash
apisniff probe redfin.com
```

Sends three parallel HTTP requests with different client profiles (bare Python, Chrome TLS impersonation, Chrome TLS + bot UA) and classifies defenses from the differential response. Detects 25 vendors including Cloudflare, Akamai, DataDome, PerimeterX, Imperva, Kasada, and more.

```bash
# JSON output for scripting
apisniff probe redfin.com --json

# Route through a proxy
apisniff probe redfin.com --proxy socks5://127.0.0.1:1080

# Include auth headers
apisniff probe api.example.com --header "Authorization:Bearer token123"

# Skip GraphQL detection
apisniff probe example.com --skip-graphql
```

### `recon` — Capture + classify

Browse a site through a local proxy. The tool classifies every request in real-time.

```bash
apisniff recon example.com
```

Launches mitmproxy on `127.0.0.1:8080` and opens Chrome with an isolated profile pointed at the proxy. Browse the site normally — the tool filters noise (ads, analytics, telemetry, third-party domains), detects antibot JS, and writes classified flows to a JSONL file. Press Ctrl+C to stop.

### `spec` — Extract API structure

Generate an OpenAPI 3.x spec from captured traffic.

```bash
# From latest capture
apisniff spec example.com

# From a specific file
apisniff spec example.com --input capture.jsonl

# From a HAR file
apisniff spec example.com --input traffic.har --format json

# Write to file
apisniff spec example.com --output spec.yaml
```

### `share` — Export shareable summary

Create a directory of derived artifacts that can be safely shared. Contains an OpenAPI spec, endpoint inventory, session metadata, and redacted report — no raw traffic.

```bash
# Share the latest capture for a domain
apisniff share example.com

# Share a specific bundle
apisniff share ~/apisniff-captures/example-com_2026-05-12_14-30

# Specify output location
apisniff share example.com --output ./for-teammate/
```

Output files:
- `spec.yaml` — OpenAPI 3.0.3 spec generated from captured traffic
- `inventory.json` — endpoint summary (method, path, status codes, content types, counts)
- `session.json` — capture metadata (domain, duration, flow counts)
- `report.md` — recon report (vendors, auth patterns, cookie names — no values)
- `graphql-schema.json` — GraphQL introspection result (if captured)

## Important Warnings

### Your IP address is exposed

**This tool sends real HTTP requests from your IP address to the target site.** Aggressive or repeated probing can get your IP rate-limited or blocked by the target. `--probe-rate` is opt-in because it fires 20 rapid requests — use it deliberately. If you don't want to expose your home or office IP, route through a proxy with `--proxy`.

Results also reflect your current IP's reputation. Residential IPs typically see fewer challenges than datacenter/cloud IPs. Running from AWS/GCP/VPS will trigger stricter defenses. Use `--proxy` to test from different IP types and compare results.

### Capture files contain sensitive data

The `recon` and `analyze` commands capture **full HTTP traffic** including cookies, auth tokens, API keys, session data, and form submissions. Raw capture bundles are stored locally in `~/apisniff-captures/` with owner-only permissions. **Raw bundles are private by design** — they are never safe to share, commit to git, or upload.

To create a shareable summary, use the `share` command:

```bash
# Export derived artifacts from the latest capture
apisniff share example.com

# From a specific bundle directory
apisniff share ~/apisniff-captures/example-com_2026-05-12_14-30

# Specify output location
apisniff share example.com --output ./to-share/
```

The shared output contains only derived artifacts — an OpenAPI spec, endpoint inventory, session metadata, and a redacted report. **No raw request/response bodies, no headers, no cookies, no query parameter values.** The output is intentionally non-replayable.

### About the mitmproxy certificate

The `recon` command requires trusting mitmproxy's CA certificate (one-time setup via macOS Keychain). This certificate allows the local proxy to inspect HTTPS traffic. It is safe because:

- **The proxy is entirely local.** It runs on `127.0.0.1:8080` on your machine. Only traffic from applications explicitly pointed at port 8080 goes through the proxy. Regular browsing, apps, and system traffic are completely unaffected.
- **The certificate is inert when the proxy is off.** With the proxy stopped, the certificate does nothing.
- **mitmproxy is an industry-standard tool.** 43,000+ GitHub stars, maintained since 2012, used by security professionals and development teams worldwide for traffic analysis and testing.

## What to do with the spec

```bash
# Generate a Python client
openapi-generator generate -i spec.yaml -g python -o client/

# Import into Postman
# File → Import → select spec.yaml

# Feed to an LLM
cat spec.yaml | llm "write a Python client for this API"
```

## License

MIT

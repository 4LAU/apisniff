# Getting Started

This guide walks through a complete API reconnaissance workflow: probe a target, capture live traffic, generate an API spec, replay for drift, and share a safe summary.

## Install

```bash
brew tap 4LAU/tap && brew install apisniff
```

From source:

```bash
go build -ldflags="-s -w" -o apisniff ./cmd/apisniff
```

## Step 1: Probe the Target

```bash
apisniff probe example.com
```

Probe compares multiple client profiles and reports a verdict plus vendor signals. It sends real requests from your network.

## Step 2: Capture Traffic

```bash
apisniff recon example.com
```

By default, `recon` opens a clean Chrome (no automation fingerprint) routed through a local MITM proxy. Log in by hand and exercise the parts of the app you want to capture, then close the browser window (or press Ctrl+C) to finish. Because the proxy sees the wire, it captures the **real Cookie/Set-Cookie headers on XHR/fetch**, so authenticated captures are replayable. The launched Chrome accepts the proxy's certificates via a command-line flag (`--ignore-certificate-errors-spki-list`) — nothing is installed in your OS trust store and there is no keychain prompt. Chrome shows a harmless "unsupported command-line flag" warning bar (browser UI only).

To capture WebSocket frames or attach to an existing browser, opt into a CDP mode (`--mode cdp-launch` / `--mode cdp-attach`). CDP modes do **not** capture Cookie/Set-Cookie on XHR/fetch.

To run only the proxy without launching a browser:

```bash
apisniff recon example.com --no-browser --port 8080
```

Route your own browser or client through `http://127.0.0.1:8080`. For HTTPS capture, trust `~/.apisniff/ca-cert.pem` in that client profile yourself. The CA private key is stored at `~/.apisniff/ca-key.pem`; treat it as sensitive local configuration.

Results are saved to `~/apisniff-captures/<domain>_<timestamp>/`.

## Already Have a Capture?

```bash
apisniff analyze traffic.har
apisniff analyze burp-export.xml
apisniff analyze flows.jsonl
```

## Step 3: Generate an API Spec

```bash
apisniff spec example.com -o spec.yaml
```

The spec includes observed endpoints, normalized path parameters, inferred request/response schemas, query parameters, and observed auth signals.

## Step 4: Replay for Drift

```bash
apisniff replay example.com
```

Replay compares status codes, JSON shape, and response sizes. It only sends safe methods by default.

## Step 5: Share Results

```bash
apisniff share example.com
```

The share directory contains `spec.yaml`, `inventory.json`, `report.md`, and `session.json`. It excludes raw traffic and redacts cookie values.

## Next Steps

- [Workflow recipes](workflows.md)
- [Capture formats](capture-formats.md)
- [Command reference](../commands/)
- [CLI spec](../spec.md)

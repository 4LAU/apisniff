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

By default, `recon` launches Chrome and captures via Chrome DevTools Protocol. Browse the site normally in that Chrome session, then wait for the command to finish or stop it with Ctrl+C where appropriate.

For the MITM proxy fallback:

```bash
apisniff recon example.com --mode proxy --port 8080
```

Route a browser or client through `http://127.0.0.1:8080`. For HTTPS capture, trust `~/.apisniff/ca-cert.pem` in that client profile. The CA private key is stored at `~/.apisniff/ca-key.pem`; treat it as sensitive local configuration.

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

# Phase 0 Spikes

This directory contains the Phase 0 risk spikes from `PLAN-GO-PORT.md`.

## Spikes

- `spikes/surf`: validates Surf Chrome impersonation against a TLS echo endpoint and real target pass/block signals.
- `spikes/cdp`: validates CDP capture into Python-compatible `CapturedFlow` JSONL.
- `spikes/fixtures`: validates golden fixture loading, stub classification, normalized comparison, and diff output.

## Required Commands

When Go 1.25+ is available:

```sh
go run ./spikes/surf --targets https://www.cloudflare.com,https://www.akamai.com,https://datadome.co
go run ./spikes/cdp --url https://example.com --out /tmp/apisniff-cdp-flows.jsonl --findings /tmp/apisniff-cdp-findings.md
go run ./spikes/fixtures
```

Then run formatting and module resolution:

```sh
gofmt -w spikes
go mod tidy
go test ./...
```

## Current Verification Status

This worktree has Chrome installed at `/Applications/Google Chrome.app`, and Go is available via Homebrew at `/opt/homebrew/bin/go`.

The spike packages compile with `go test ./...`. The fixture harness passes. Surf and CDP have been tested against live/local targets. The detailed gate evidence is in `spikes/PHASE0-RESULTS.md`.

The Phase 0 decision gate is satisfied with the caveats documented in `spikes/PHASE0-RESULTS.md`.

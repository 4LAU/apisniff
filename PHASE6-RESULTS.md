# Phase 6 Results: Share, Report, Proxy Mode

Status: complete.

## Implemented

- Added `apisniff share BUNDLE|DOMAIN`.
- Added safe derived export:
  - `spec.yaml`
  - `inventory.json`
  - `report.md`
  - `session.json`
- Raw traffic is not copied into share output.
- Cookie values are redacted as `[redacted]` in inventory/report output.
- Added Markdown reporting with:
  - flow count
  - surface category breakdown
  - top endpoints
  - observed auth patterns
  - cookie summary
  - host summary
- Added `recon --mode proxy` using `goproxy`.
- Proxy mode:
  - listens on the requested port
  - supports HTTP and HTTPS MITM capture
  - generates/loads a local CA at `~/.apisniff/ca-cert.pem`
  - stores private key at `~/.apisniff/ca-key.pem`
  - converts proxied responses to `CapturedFlow`
  - classifies and writes kept flows to JSONL
  - writes `session.json`
  - shuts down on context cancellation, SIGINT, SIGTERM, or timeout

## Validation

- Added share/report tests for redaction and safe export scope.
- Added proxy tests for:
  - HTTP proxied capture
  - HTTPS MITM capture with the generated CA
- Ran a CLI proxy smoke test:
  - built `apisniff`
  - started `recon 127.0.0.1 --mode proxy --port 9878 --json`
  - sent a request through the proxy
  - interrupted the proxy
  - verified JSON output, `flows.jsonl`, and captured flow contents
- Ran full test suite:
  - `go test ./...`

## Notes

- Proxy mode returns the generated CA path in JSON output as `ca_path`.
- Clients must trust `~/.apisniff/ca-cert.pem` for HTTPS MITM capture outside tests.

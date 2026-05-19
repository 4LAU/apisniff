# Phase 4 Results

Date: 2026-05-19

## Verdict

Phase 4 passes.

Implemented:

- Format detection for JSONL, HAR, and Burp XML.
- HAR adapter:
  - `log.entries` parsing
  - request/response headers
  - request body
  - base64 response body decoding
  - ISO 8601 timestamp parsing
  - duplicate header joining with newline for `set-cookie`
- Burp XML adapter:
  - `items/item` parsing
  - base64 and plain request/response messages
  - raw HTTP header/body splitting
  - duplicate `set-cookie` preservation
- `analyze FILE` now accepts HAR, Burp XML, and JSONL.
- `spec --input FILE` now accepts HAR, Burp XML, and JSONL.

## Verification

```sh
gofmt -w internal
go test ./...
go run ./cmd/apisniff analyze sample.har --json
go run ./cmd/apisniff analyze sample.xml --json
go run ./cmd/apisniff spec example.com --input sample.har --format json
go run ./cmd/apisniff spec example.com --input sample.xml --format json
```

Results:

- `go test ./...` passed.
- HAR analyze returned one flow with `/v1/items`.
- Burp analyze returned one flow with `/api/items`.
- HAR and Burp inputs both generated OpenAPI 3.0.3 specs.

## Notable Fix

The first CLI spec verification exposed a variable shadowing bug: the requested output format was overwritten by the detected input format. This is fixed, and `--format json` now emits JSON for HAR/Burp/JSONL inputs.

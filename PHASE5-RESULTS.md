# Phase 5 Results: Replay Command

Status: complete.

## Implemented

- Added `apisniff replay BUNDLE|DOMAIN|FLOWS_JSONL`.
- Added safe flow selection:
  - `GET`, `HEAD`, and `OPTIONS` replay by default.
  - `--include-unsafe` includes mutating methods.
  - `--filter` applies glob matching to captured paths.
- Added Netscape `cookies.txt` parsing and domain cookie injection.
- Added replay request preparation:
  - Preserves captured query strings.
  - Removes hop-by-hop headers.
  - Supports `--header/-H` auth/header injection.
  - Uses Surf impersonation for Chrome/Firefox replay.
- Added replay diffing:
  - Status comparison.
  - JSON body shape comparison to depth 3.
  - Response size tracking.
  - Categories: `match`, `drift`, `auth_expired`, `blocked`, `error`.
- Added JSON output, text output, `--output`, and `--dry-run`.

## Validation

- Added unit tests for cookies, flow selection, request preparation, JSON shape drift, category assignment, and golden dry-run replay fixtures.
- Ran a local CLI smoke test against a temporary HTTP server:
  - `go run ./cmd/apisniff replay /tmp/.../flows.jsonl --json`
  - `go run ./cmd/apisniff replay /tmp/.../flows.jsonl --dry-run`
- Ran full test suite:
  - `go test ./...`

## Notes

- Replay accepts JSONL captures or bundle/domain references resolving to `flows.jsonl`.
- Surf defaults to insecure TLS verification, so replay explicitly enables certificate validation unless `--insecure` is passed.

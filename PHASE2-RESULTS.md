# Phase 2 Results

Date: 2026-05-19

## Verdict

Phase 2 passes.

Implemented:

- `internal/classify` with the Python classifier decision order:
  - OPTIONS drop
  - allowlist domain/path handling
  - noise domain drops
  - CSP related-domain learning
  - path telemetry drops using path-only matching
  - third-party drops
  - static asset drops
  - antibot JavaScript keep behavior
  - same-site telemetry/noise drops
  - Akamai `sensor_data` drops
  - telemetry subdomain drops
- `internal/auth` with auth pattern detection and cookie extraction/export.
- CDP `recon` now uses the real classifier instead of the Phase 1 stub.
- `analyze --json` includes auth patterns and extracted cookies.

## Verification

```sh
gofmt -w internal
go test ./...
go run ./cmd/apisniff recon http://127.0.0.1:8765/ --headless --port 9335 --wait 4s --json
go run ./cmd/apisniff analyze /Users/aaron/apisniff-captures/127-0-0-1:8765_2026-05-19_00-13-16/flows.jsonl --json
```

Results:

- `go test ./...` passed.
- Classifier parity tests cover the Python `tests/test_classify.py` cases, including:
  - noise domains
  - allowlisted challenge domains
  - third-party drops
  - related-domain learning from Referer
  - static asset drops
  - antibot JS preservation
  - telemetry path behavior
  - OPTIONS drops
  - private suffix behavior for `herokuapp.com`
  - query string false-positive avoidance
- Auth tests cover bearer/basic auth, API key headers/query params, session cookies, token endpoints, Set-Cookie parsing, deduplication, and Netscape cookie jar export.
- Recon with the real classifier observed 10 flows, kept 9, and dropped `favicon.ico` as path telemetry.

## Notes For Phase 3

- Kept flows now include `category:<surface_category>` tags. Phase 3 can use those tags for default flow selection until a richer serialized surface metadata format is added.
- The Go classifier intentionally strips ports before registered-domain extraction so local and non-standard-port recon targets classify correctly.

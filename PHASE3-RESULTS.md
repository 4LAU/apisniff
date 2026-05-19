# Phase 3 Results

Date: 2026-05-19

## Verdict

Phase 3 passes.

Implemented:

- `internal/spec` OpenAPI 3.0.3 generator.
- API-flow filtering from content type and classification tags.
- Path normalization via `model.NormalizePath`.
- Query parameter aggregation.
- Response schema inference and merging.
- JSON, form-url-encoded, and multipart request body schemas.
- File-field detection as `format: binary`.
- Example inclusion with secret and sensitive-field redaction.
- Observed auth extensions and optional security scheme inference.
- `apisniff spec DOMAIN --input FILE --format yaml|json --output FILE`.

## Verification

```sh
gofmt -w internal
go test ./...
go run ./cmd/apisniff spec 127.0.0.1:8765 \
  --input /Users/aaron/apisniff-captures/127-0-0-1:8765_2026-05-19_00-13-16/flows.jsonl \
  --format json
go run ./cmd/apisniff spec 127.0.0.1:8765 \
  --input /Users/aaron/apisniff-captures/127-0-0-1:8765_2026-05-19_00-13-16/flows.jsonl \
  --format yaml
```

Results:

- `go test ./...` passed.
- The local captured flow set generated an OpenAPI 3.0.3 document.
- API-flow filtering selected JSON/API endpoints from the real recon output:
  - `/cached`
  - `/json-small`
  - `/json-1mb`
  - `/json-10mb`
  - `/sw-controlled`

## Notes For Phase 4

- HAR and Burp adapters can feed the same `model.CapturedFlow` shape used by `spec`.
- YAML output is structurally correct; if strict byte-for-byte golden parity is required later, add ordered YAML emission to match Python key ordering exactly.

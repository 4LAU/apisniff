# Phase 1 Results

Date: 2026-05-18

## Verdict

Phase 1 vertical slice passes.

Implemented:

- `cmd/apisniff` Go entrypoint.
- Cobra CLI skeleton for `probe`, `recon`, `analyze`, `replay`, `spec`, and `share`.
- Data models and JSONL-compatible `CapturedFlow` base64 body encoding.
- Surf + raw HTTP probe variants.
- Embedded vendor signature detection from `vendors.json`.
- Basic GraphQL endpoint detection.
- CDP-based `recon` in `cdp-launch` and `cdp-attach` modes.
- Atomic JSONL writer and session metadata.
- JSONL-only `analyze` loader with endpoint summary.

## Verification

```sh
gofmt -w cmd internal spikes
go mod tidy
go test ./...
go run ./cmd/apisniff --help
go run ./cmd/apisniff probe https://example.com --json
go run ./cmd/apisniff recon http://127.0.0.1:8765/ --headless --port 9334 --wait 3s --json
go run ./cmd/apisniff analyze /Users/aaron/apisniff-captures/127-0-0-1:8765_2026-05-18_23-56/flows.jsonl --json
```

Results:

- `go test ./...` passed.
- `probe https://example.com --json` returned `no_protection` with three successful probe variants.
- `recon` captured 10 CDP flows to JSONL from the local matrix page.
- `analyze` loaded that JSONL and summarized the captured endpoints.

## Notes For Phase 2

- `recon` currently uses a stub classifier that keeps most non-static flows. Phase 2 should replace this with the real classification engine.
- `replay`, `spec`, and `share` are CLI skeletons only.
- `proxy` recon mode is reserved but not implemented in Phase 1.
- Surf proxy/profile options are minimal in this vertical slice; harden them when probe behavior is expanded.

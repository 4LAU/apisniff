# Golden Fixture Harness Spike

This spike checks whether a Go harness can load Python-shaped golden fixtures, run a classifier, and report a readable JSON diff.

Run from the repository root:

```sh
go run ./spikes/fixtures
```

Optional flags:

```sh
go run ./spikes/fixtures \
  --flows testdata/golden/phase0/classify/flows.jsonl \
  --expected testdata/golden/phase0/classify/expected.json
```

## Fixture Format

`flows.jsonl` is newline-delimited JSON using the Python `CapturedFlow.to_dict()` shape:

- `method`, `host`, `path`, `url`
- `request_headers`, `response_headers`
- `request_body` and `response_body` as base64 strings or `null`
- `_body_encoding` set to `base64`
- `response_status`, `tags`, `timestamp`

`expected.json` is a JSON array of `ClassifyResult`-like objects:

- `action`: `keep` or `drop`
- `category`: drop category or an empty string for kept flows
- `flow`: `null` for drops, or the kept flow with classifier-added tags

The classifier in this spike is intentionally hardcoded by `method host path`. It proves fixture loading, normalized JSON comparison, and diff reporting only; it is not real classification logic.

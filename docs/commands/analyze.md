# `apisniff analyze`

Load HAR, Burp XML, or JSONL traffic and summarize endpoints, auth patterns, and cookies.

## Usage

```bash
apisniff analyze INPUT_FILE [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--domain`, `-d` | | Target domain label for output |
| `--json` | `false` | Include full converted flows in JSON output |
| `--output-dir` | | Write a capture bundle (`flows.jsonl`, `session.json`, `report.md`, and `openapi-spec.yaml` when the traffic yields API flows) to this directory |
| `--fetch-graphql` | `false` | Fetch the GraphQL schema by introspection. Requires `--output-dir` |

## Examples

```bash
apisniff analyze traffic.har
apisniff analyze burp-export.xml --domain api.example.com
apisniff analyze ~/apisniff-captures/example-com_2026-05-12/flows.jsonl --json

# Convert imported traffic into a bundle the other commands can read
apisniff analyze traffic.har --output-dir ./example-com-import
apisniff spec ./example-com-import -o openapi.yaml

# Also introspect any GraphQL endpoints found in the traffic
apisniff analyze traffic.har --output-dir ./bundle --fetch-graphql
```

## `--output-dir` bundles are not managed

Only `recon` creates bundles that `bundles` and `clean` know about — those live
in `~/apisniff-captures/` under a `<domain>_<timestamp>` name. A directory you
name with `--output-dir` is never listed by `apisniff bundles` and never removed
by `apisniff clean`, even if you put it inside `~/apisniff-captures/`, and
`apisniff spec example.com` will not find it by domain. Pass the directory
itself: `apisniff spec ./example-com-import`.

That matters because the bundle holds real session cookies from the imported
traffic. Nothing will clean it up for you — delete it yourself when you're done.

Write each import to a **fresh** directory. Reusing one overwrites what it can
but leaves anything the new run does not produce: a run whose traffic yields no
API flows keeps the previous `openapi-spec.yaml`, and a run without
`--fetch-graphql` keeps the previous `graphql.json`. Either way the stale file
describes the older capture.

## GraphQL introspection

`--fetch-graphql` sends a full introspection query to each GraphQL endpoint
found in the traffic and stores the schema in the bundle. This is a **live
request** — the endpoint must be reachable now and must still allow
introspection, which many production APIs disable. It does not recover a schema
from the captured traffic alone.

The introspection request is **unauthenticated** — apisniff does not replay the
captured session's cookies or auth headers, so an endpoint that requires a login
answers `401`/`403` and no schema comes back. Per-endpoint failures are recorded
in `graphql.json` alongside any schemas that did land; the command still exits
`0`, so check that file rather than the exit code.

Without `--output-dir` there is nowhere to put the result, so the command exits
with `--fetch-graphql requires --output-dir to store the introspection result`.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

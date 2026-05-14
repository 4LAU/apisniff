<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff share`

Export a shareable summary from a capture bundle. Produces only derived artifacts (spec, inventory, report, session metadata). No raw traffic, no credentials, no cookie values.

## Usage

```
Usage: apisniff share [OPTIONS] BUNDLE

 Export a shareable summary — no raw traffic, no credentials.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    bundle      TEXT  Bundle directory path or domain name [required]       │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --output  -o      TEXT  Output directory (default: <bundle>-shared)          │
│ --domain  -d      TEXT  Domain (auto-detected from session.json if omitted)  │
│ --help                  Show this message and exit.                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Examples

```bash
# Share the latest capture for a domain
apisniff share example.com

# Share a specific bundle directory
apisniff share ~/apisniff-captures/example-com_2026-05-12

# Specify output directory
apisniff share example.com -o ./for-teammate/
```

### What's included

| File | Contents |
|------|----------|
| `spec.yaml` | OpenAPI 3.0.3 specification |
| `inventory.json` | Endpoint summary (method, path, status codes, counts) |
| `session.json` | Capture metadata (domain, duration, flow counts) |
| `report.md` | Recon report with redacted cookie values |
| `graphql-schema.json` | GraphQL schema (if captured) |

### What's excluded

Raw traffic (`flows.jsonl`), cookies (`cookies.txt`), request/response headers, query
parameter values. The output is intentionally non-replayable.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

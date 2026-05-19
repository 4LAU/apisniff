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
| `--output-dir` | | Reserved for future bundle writing |
| `--fetch-graphql` | `false` | Reserved for future GraphQL schema fetching |

## Examples

```bash
apisniff analyze traffic.har
apisniff analyze burp-export.xml --domain api.example.com
apisniff analyze ~/apisniff-captures/example-com_2026-05-12/flows.jsonl --json
```

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

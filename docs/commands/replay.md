# `apisniff replay`

Replay captured API calls and categorize drift.

## Usage

```bash
apisniff replay BUNDLE|DOMAIN|FLOWS_JSONL [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--filter` | | Glob filter for captured paths |
| `--timeout` | `15s` | Request timeout |
| `--cookie-file` | | Netscape `cookies.txt` path |
| `--header`, `-H` | | Extra replay header as `key:value` |
| `--json` | `false` | Output as JSON |
| `--output`, `-o` | | Write JSON output to file |
| `--dry-run` | `false` | List selected endpoints without replaying |
| `--include-unsafe` | `false` | Include non-GET/HEAD/OPTIONS methods |
| `--insecure` | `false` | Skip TLS verification |
| `--impersonate` | `chrome` | Surf profile: `chrome` or `firefox` |
| `--forward-auth` | `false` | Forward auth headers captured in flows |

## Examples

```bash
apisniff replay example.com
apisniff replay ~/apisniff-captures/example-com_2026-05-12 --dry-run
apisniff replay flows.jsonl --filter "/api/v1/users*"
apisniff replay example.com --cookie-file cookies.txt -H "Authorization: Bearer token"
apisniff replay example.com --include-unsafe --json -o replay.json
```

By default, replay sends only safe methods: `GET`, `HEAD`, and `OPTIONS`, and strips auth headers captured in flows. Use `--header` or `--cookie-file` to provide fresh credentials, or `--forward-auth` to replay captured auth headers deliberately.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

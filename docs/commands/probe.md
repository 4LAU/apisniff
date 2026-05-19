# `apisniff probe`

Assess a URL before capture by comparing normal Go, Surf Chrome, and headless-browser client behavior.

## Usage

```bash
apisniff probe URL [flags]
apisniff probe rate URL [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output as JSON |
| `--proxy` | | Route probes through an upstream proxy |
| `--header`, `-H` | | Extra header as `key:value` |
| `--cookie` | | Cookie header value |
| `--insecure` | `false` | Skip TLS verification |
| `--impersonate` | `chrome` | TLS profile |

## Examples

```bash
apisniff probe example.com
apisniff probe example.com --json
apisniff probe example.com --proxy socks5://127.0.0.1:1080
apisniff probe api.example.com -H "Authorization: Bearer tok123"
apisniff probe rate example.com
```

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

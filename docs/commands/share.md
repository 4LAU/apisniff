# `apisniff share`

Export a safe, shareable summary from a capture bundle.

## Usage

```bash
apisniff share BUNDLE|DOMAIN [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `<bundle>/share` | Output directory |
| `--domain` | session domain | Domain override |
| `--json` | `false` | Output result as JSON |

## Examples

```bash
apisniff share example.com
apisniff share ~/apisniff-captures/example-com_2026-05-12
apisniff share example.com -o ./for-teammate --json
```

## Included

| File | Contents |
|------|----------|
| `spec.yaml` | OpenAPI 3.0.3 generated from kept flows |
| `inventory.json` | Endpoint, host, category, auth, and redacted cookie summary |
| `report.md` | Markdown summary with redacted cookie values |
| `session.json` | Capture metadata |

## Excluded

Raw traffic (`flows.jsonl`) and cookie values. The share output is designed for review, not replay.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

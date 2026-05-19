# `apisniff spec`

Generate an OpenAPI 3.0.3 specification from captured traffic.

## Usage

```bash
apisniff spec DOMAIN [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input`, `-i` | latest bundle | Input file: JSONL, HAR, or Burp XML |
| `--format`, `-f` | `yaml` | Output format: `yaml` or `json` |
| `--output`, `-o` | stdout | Output file path |
| `--surface-output` | | Reserved surface output path |
| `--include-third-party` | `false` | Reserved third-party inclusion flag |
| `--include-category` | | Reserved category inclusion flag |
| `--include-host` | | Reserved host inclusion flag |
| `--infer-security-schemes` | `false` | Emit OpenAPI security schemes from observed auth |
| `--no-infer-security-schemes` | `false` | Compatibility flag; observed auth remains in extensions |
| `--examples` | `false` | Include redacted examples |

## Examples

```bash
apisniff spec example.com
apisniff spec example.com -i capture.jsonl -f json -o spec.json
apisniff spec example.com -i traffic.har -o spec.yaml
apisniff spec example.com --infer-security-schemes --examples
```

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

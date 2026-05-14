<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff spec`

Generate an OpenAPI 3.0.3 specification from captured traffic. Groups requests by normalized path, infers schemas from response bodies, merges across multiple observations, and detects auth patterns.

## Usage

```
Usage: apisniff spec [OPTIONS] DOMAIN

 Extract API structure -- generate OpenAPI from captured traffic.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    domain      TEXT  Domain to generate spec for [required]                │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --input                      -i      TEXT         Input file (JSONL, HAR, or │
│                                                   mitmproxy flow)            │
│ --format                     -f      [yaml|json]  Output format: yaml or     │
│                                                   json                       │
│                                                   [default: yaml]            │
│ --output                     -o      TEXT         Output file path           │
│ --no-infer-security-schemes                       Keep observed auth in      │
│                                                   extensions only            │
│ --no-examples                                     Omit sample response       │
│                                                   values from generated spec │
│ --help                                            Show this message and      │
│                                                   exit.                      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Examples

```bash
# Generate spec from latest capture (YAML to stdout)
apisniff spec example.com

# From a specific input file
apisniff spec example.com -i capture.jsonl

# JSON format
apisniff spec example.com -f json

# Write to file
apisniff spec example.com -o spec.yaml

# Omit example values from captured data
apisniff spec example.com --no-examples

# From a HAR file, JSON format
apisniff spec example.com -i traffic.har -f json -o spec.json
```

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

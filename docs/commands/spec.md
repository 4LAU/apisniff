<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff spec`

Generate an OpenAPI 3.0.3 specification from captured traffic. Groups requests by normalized path, infers schemas from response bodies, merges across multiple observations, detects auth patterns, and writes a safe surface inventory for important traffic excluded from the clean OpenAPI view.

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
│ --surface-output                     TEXT         Write categorized surface  │
│                                                   inventory JSON to this     │
│                                                   path                       │
│ --include-third-party                             Include third-party        │
│                                                   API-shaped dependencies in │
│                                                   OpenAPI output             │
│ --include-category                   TEXT         Include a surface category │
│                                                   in OpenAPI output;         │
│                                                   repeatable                 │
│ --include-host                       TEXT         Include API-shaped traffic │
│                                                   from a host in OpenAPI     │
│                                                   output; repeatable         │
│ --no-infer-security-schemes                       Keep observed auth in      │
│                                                   extensions only            │
│ --examples                                        Include sample values from │
│                                                   captured traffic in        │
│                                                   generated spec             │
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

# Include sample values from captured data
apisniff spec example.com --examples

# Include third-party API-shaped dependencies
apisniff spec example.com --include-third-party

# Intentionally expose challenge endpoints in the spec
apisniff spec example.com --include-category antibot --include-category captcha

# Include API-shaped traffic from a specific host
apisniff spec example.com --include-host api.example.com

# From a HAR file, JSON format
apisniff spec example.com -i traffic.har -f json -o spec.json
```

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

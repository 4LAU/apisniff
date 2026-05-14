<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff analyze`

Import a traffic capture file (HAR, Burp XML, or JSONL), run the same classification pipeline as recon, and produce a full bundle with report.

## Usage

```
Usage: apisniff analyze [OPTIONS] INPUT_FILE

 Offline analysis -- import traffic capture, classify, extract everything.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    input_file      TEXT  Input file (HAR, Burp XML, or JSONL) [required]   │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --domain         -d      TEXT  Target domain (auto-detected if omitted)      │
│ --json                         Output session stats as JSON                  │
│ --output-dir             TEXT  Directory to write bundle (default:           │
│                                ~/apisniff-captures/)                         │
│ --fetch-graphql                Fetch GraphQL schema from detected endpoints  │
│ --help                         Show this message and exit.                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Examples

```bash
# Analyze a HAR file exported from Chrome DevTools
apisniff analyze traffic.har

# Analyze a Burp Suite export
apisniff analyze burp-export.xml

# Analyze a previous apisniff capture
apisniff analyze ~/apisniff-captures/example-com_2026-05-12/flows.jsonl

# Specify the domain explicitly
apisniff analyze traffic.har --domain api.example.com

# Write results to a specific directory
apisniff analyze traffic.har --output-dir ./my-analysis/

# Fetch GraphQL schemas from detected endpoints
apisniff analyze traffic.har --fetch-graphql
```

---

[All commands](../README.md#commands) · [CLI spec](../spec.md)

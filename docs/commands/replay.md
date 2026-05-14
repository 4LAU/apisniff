<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff replay`

Replay captured API calls against the live site and detect drift. Compares response status, structure, and size. Categorizes each endpoint as match, drift, auth_expired, blocked, or error.

## Usage

```
Usage: apisniff replay [OPTIONS] BUNDLE

 Replay captured API calls and detect drift.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    bundle      TEXT  Bundle directory path or domain name [required]       │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --filter                  TEXT  Glob filter for paths                        │
│ --cookie-file             TEXT  Netscape cookies.txt path                    │
│ --header          -H      TEXT  Extra header (key:value)                     │
│ --json                          Output as JSON                               │
│ --output          -o      TEXT  Write JSON output to file                    │
│ --dry-run                       List endpoints without replaying             │
│ --include-unsafe                Include non-GET/HEAD/OPTIONS methods         │
│ --insecure                      Skip TLS verification                        │
│ --help                          Show this message and exit.                  │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Examples

```bash
# Replay the latest capture for a domain
apisniff replay example.com

# Replay a specific bundle directory
apisniff replay ~/apisniff-captures/example-com_2026-05-12

# Preview which endpoints would be replayed
apisniff replay example.com --dry-run

# Filter to specific paths
apisniff replay example.com --filter "/api/v1/users*"

# Use saved cookies for authenticated endpoints
apisniff replay example.com --cookie-file ~/apisniff-captures/example-com_2026-05-12/cookies.txt

# Include POST/PUT/DELETE endpoints (use with care)
apisniff replay example.com --include-unsafe

# JSON output for scripting
apisniff replay example.com --json -o results.json
```

---

[All commands](../README.md#commands) · [CLI spec](../spec.md)

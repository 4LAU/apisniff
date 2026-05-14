<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff probe`

Assess what defenses protect a URL before you capture traffic. Sends three parallel requests with different client profiles and classifies the differential response. Detects 25+ vendor products (Cloudflare, Akamai, DataDome, etc.).

## Usage

```
Usage: apisniff probe [OPTIONS] TARGET...

 Defense preflight -- what kind of surface am I dealing with?

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    target      TARGET...  URL to probe, or `rate URL` to check rate        │
│                             limiting                                         │
│                             [required]                                       │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --json                    Output as JSON                                     │
│ --proxy             TEXT  Route probes through proxy (SOCKS5/HTTP)           │
│ --header    -H      TEXT  Extra header (key:value)                           │
│ --cookie            TEXT  Cookie header value                                │
│ --insecure                Skip TLS verification                              │
│ --help                    Show this message and exit.                        │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Examples

```bash
# Quick defense check
apisniff probe example.com

# With JSON output for scripting
apisniff probe example.com --json

# Route through a proxy
apisniff probe example.com --proxy socks5://127.0.0.1:1080

# Include auth headers for authenticated endpoints
apisniff probe api.example.com -H "Authorization:Bearer tok123"

# Detect rate limiting (fires 20 rapid requests)
apisniff probe rate example.com
```

---

[All commands](../README.md#commands) · [CLI spec](../spec.md)

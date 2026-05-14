<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff probe`

Assess what defenses protect a URL before you capture traffic. Sends three parallel requests with different client profiles and classifies the differential response. Detects 25+ vendor products (Cloudflare, Akamai, DataDome, etc.).

## Usage

```
Usage: apisniff probe [OPTIONS] URL                                            
                                                                                
 Defense preflight -- what kind of surface am I dealing with?                   
                                                                                
╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    url      TEXT  URL to probe (e.g. redfin.com) [required]                │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --json                        Output as JSON                                 │
│ --proxy                 TEXT  Route probes through proxy (SOCKS5/HTTP)       │
│ --header        -H      TEXT  Extra header (key:value)                       │
│ --cookie                TEXT  Cookie header value                            │
│ --skip-graphql                Skip GraphQL endpoint detection                │
│ --impersonate           TEXT  TLS profile: chrome, chrome131, chrome120,     │
│                               safari17_0, firefox133                         │
│                               [default: chrome]                              │
│ --probe-rate                  Send 20 requests to detect rate limiting       │
│                               (opt-in)                                       │
│ --insecure                    Skip TLS verification                          │
│ --help                        Show this message and exit.                    │
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
apisniff probe example.com --probe-rate

# Use a specific TLS profile
apisniff probe example.com --impersonate safari17_0
```

---

[All commands](../README.md#commands) · [CLI spec](../spec.md)

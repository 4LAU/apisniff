<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->


# `apisniff recon`

Browse a site through a local mitmproxy, classify every request in real-time. Preserves captured traffic before projection, detects antibot JS, and writes classified flows plus surface metadata to a bundle directory.

## Usage

```
Usage: apisniff recon [OPTIONS] DOMAIN

 Capture + classify -- browse a site through the proxy, classify everything.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    domain      TEXT  Domain to capture traffic from [required]             │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --json                  Output as JSON                                       │
│ --proxy        TEXT     Upstream proxy for mitmproxy                         │
│ --port         INTEGER  Local proxy port [default: 8080]                     │
│ --help                  Show this message and exit.                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Examples

```bash
# Start capturing traffic for a domain
apisniff recon example.com

# Use a different local port
apisniff recon example.com --port 9090

# Route through an upstream proxy
apisniff recon example.com --proxy http://corporate-proxy:3128
```

Browse the site in the Chrome window that opens. Press **Ctrl+C** to stop capture.

For HTTPS traffic, the proxied browser must trust mitmproxy's local CA certificate.
Start recon, open `http://mitm.it` in the launched Chrome window, and follow
mitmproxy's platform instructions. See the README for the safety notes.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

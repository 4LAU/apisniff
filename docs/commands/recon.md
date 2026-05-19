# `apisniff recon`

Capture and classify browser/client traffic.

## Usage

```bash
apisniff recon DOMAIN [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output capture result as JSON |
| `--port` | `9222` | CDP port, or proxy listen port in `--mode proxy` |
| `--mode` | `cdp-launch` | `cdp-launch`, `cdp-attach`, or `proxy` |
| `--remote-url` | | Chrome DevTools URL for `cdp-attach` |
| `--headless` | `false` | Launch Chrome headless in `cdp-launch` |
| `--wait` | `8s` | Extra wait after CDP navigation |
| `--proxy` | | Reserved for future upstream proxy chaining |

## Examples

```bash
# Launch Chrome and capture via CDP
apisniff recon example.com

# Launch headless Chrome
apisniff recon example.com --headless --wait 5s

# Attach to an existing Chrome DevTools endpoint
apisniff recon example.com --mode cdp-attach --remote-url http://127.0.0.1:9222

# Run the MITM proxy fallback
apisniff recon example.com --mode proxy --port 8080
```

## Capture Modes

`cdp-launch` uses Chrome DevTools Protocol. The target sees Chrome's real TLS/HTTP behavior, but JavaScript automation signals may still be present.

`cdp-attach` captures from an existing Chrome DevTools endpoint.

`proxy` starts a local MITM proxy. For HTTPS capture, route your client through `127.0.0.1:<port>` and trust `~/.apisniff/ca-cert.pem` in that client profile. The CA private key is stored at `~/.apisniff/ca-key.pem`.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

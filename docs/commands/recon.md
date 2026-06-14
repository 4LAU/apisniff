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
| `--headless` | `false` | Launch Chrome headless (`cdp-launch` and `proxy`) |
| `--no-browser` | `false` | In `proxy` mode, start only the proxy and skip launching Chrome |
| `--proxy` | | Reserved for future upstream proxy chaining |

## Examples

```bash
# Launch Chrome and capture via CDP
apisniff recon example.com

# Launch headless Chrome (Ctrl+C to stop)
apisniff recon example.com --headless

# Attach to an existing Chrome DevTools endpoint
apisniff recon example.com --mode cdp-attach --remote-url http://127.0.0.1:9222

# Proxy mode: opens a clean Chrome (no automation fingerprint) through a MITM
# proxy. Log in by hand, then close the window (or Ctrl+C) to finish.
apisniff recon example.com --mode proxy

# Proxy mode without launching a browser — point your own client at the proxy
apisniff recon example.com --mode proxy --no-browser --port 8080
```

## Capture Modes

`cdp-launch` uses Chrome DevTools Protocol. The target sees Chrome's real TLS/HTTP behavior, but JavaScript automation signals may still be present.

`cdp-attach` captures from an existing Chrome DevTools endpoint.

CDP capture records API responses, response body size metadata, and WebSocket handshake/frame summaries when Chrome exposes those events.

`proxy` starts a local MITM proxy with HTTP/2 support and, by default, launches a real Chrome routed through it. That Chrome has **no automation fingerprint** — no `--enable-automation`, no CDP attachment, so `navigator.webdriver` is false — which is what lets you log in past bot-detection vendors (DataDome, PerimeterX, etc.) that block CDP-launched browsers. It uses a fresh, disposable profile, separate from your everyday Chrome and wiped on exit, so you log in by hand each session. End the session by closing the browser's last window/tab or pressing **Ctrl+C** — apisniff detects the close by watching the launched browser's own processes (no automation hook on the page).

On macOS, proxy mode trusts the proxy CA (`~/.apisniff/ca-cert.pem`) in your login keychain automatically on first use (one-time approval, no admin), so the browser shows no certificate warning. Remove it with `security delete-certificate -c "apisniff local MITM CA"`. The CA private key is stored at `~/.apisniff/ca-key.pem` with owner-only permissions; treat it as sensitive.

Pass `--no-browser` to start only the proxy and route your own client through `127.0.0.1:<port>`, trusting `~/.apisniff/ca-cert.pem` in that client yourself.

Raw capture bundles persist until explicitly cleaned. Passive recon warns when local bundles are older than 30 days so you can review them with `apisniff bundles` and delete unneeded bundles with `apisniff clean`.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

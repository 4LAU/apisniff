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
| `--port` | auto | Default proxy mode binds an ephemeral local port; `--no-browser` uses 8080; `cdp-attach` uses 9222; `cdp-launch` auto-selects. Pass `--port` to override. |
| `--mode` | `proxy` | `proxy` (default), `cdp-launch`, or `cdp-attach` |
| `--remote-url` | | Chrome DevTools URL for `cdp-attach` |
| `--headless` | `false` | Launch Chrome headless (`cdp-launch` and `proxy`) |
| `--no-browser` | `false` | In `proxy` mode, start only the proxy and skip launching Chrome |
| `--bind` | `127.0.0.1` | Address the `proxy` listens on. Use `0.0.0.0` (all interfaces) or a LAN IP to let other devices connect. Proxy mode only; IPv6 bind addresses are not supported. |
| `--allow-client` | | Source-IP allowlist, repeatable. Only meaningful with a non-loopback `--bind`: when set, only the listed IPs (plus the local machine) may connect, and the locally launched Chrome is never blocked. Omit it and the proxy is open to anyone on the network (apisniff prints a prominent warning). |
| `--proxy` | | Reserved for future upstream proxy chaining |

## Examples

```bash
# Default: opens a clean Chrome (no automation fingerprint) through a MITM
# proxy. Log in by hand, then close the window (or Ctrl+C) to finish.
# Captures real Cookie/Set-Cookie on XHR/fetch, so the capture is replayable.
apisniff recon example.com

# Launch headless Chrome (Ctrl+C to stop)
apisniff recon example.com --headless

# Run only the proxy — point your own client at 127.0.0.1:8080
apisniff recon example.com --no-browser --port 8080

# Capture from a phone on the same LAN: bind all interfaces, then set the
# device's Wi-Fi proxy to the printed <LAN-IP>:<port> and trust
# ~/.apisniff/ca-cert.pem on the device. --allow-client restricts who can connect.
apisniff recon example.com --no-browser --bind 0.0.0.0 --allow-client 192.168.1.42

# CDP mode: capture WebSocket frames / resource_type (no XHR/fetch cookies)
apisniff recon example.com --mode cdp-launch

# Attach to an existing Chrome DevTools endpoint (same cookie limitation)
apisniff recon example.com --mode cdp-attach --remote-url http://127.0.0.1:9222
```

## Capture Modes

`proxy` (default) starts a local MITM proxy with HTTP/2 support and launches a real Chrome routed through it. That Chrome has **no automation fingerprint** — no `--enable-automation`, no CDP attachment, so `navigator.webdriver` is false — which is what lets you log in past bot-detection vendors (DataDome, PerimeterX, etc.) that block CDP-launched browsers. Because the proxy sees the wire, it captures the **real Cookie/Set-Cookie headers on XHR/fetch**, so authenticated captures are replayable. Chrome uses a fresh, disposable profile, separate from your everyday Chrome and wiped on exit, so you log in by hand each session. End the session by closing the browser's last window/tab or pressing **Ctrl+C** — apisniff detects the close by watching the launched browser's own processes (no automation hook on the page).

For HTTPS, the launched Chrome accepts the proxy's certificates via `--ignore-certificate-errors-spki-list`, which tells that one disposable Chrome to trust **only apisniff's CA, matched by its public-key hash**. Every other certificate is still validated normally; this is the narrow, scoped flag, not the blunt `--ignore-certificate-errors` that switches off all certificate checks. So when Chrome warns that "security will suffer," the relaxation is one cert wide and confined to the throwaway profile; your everyday Chrome is untouched. The hash is passed on the command line, so **nothing is installed in any OS trust store and there is no keychain prompt**. Chrome shows a cosmetic "unsupported command-line flag" warning bar (browser UI only, invisible to pages). The CA private key at `~/.apisniff/ca-key.pem` is sensitive (anything holding it can forge HTTPS certs for clients that trust the CA) and is stored with owner-only permissions.

Pass `--no-browser` to start only the proxy and route your own client through `127.0.0.1:<port>`, trusting `~/.apisniff/ca-cert.pem` in that client yourself.

To capture from another device on the same network (e.g. an iPhone), pass `--bind 0.0.0.0` (or a specific LAN IP) so the proxy accepts non-local connections. apisniff prints the device setup line — set the device's Wi-Fi proxy to the printed `<LAN-IP>:<port>` — and you must install and trust `~/.apisniff/ca-cert.pem` on the device yourself. A non-loopback bind opens the proxy to your network: by default apisniff only warns, so restrict it with `--allow-client <ip>` (repeatable) to admit only the listed device IPs. The local machine is always allowed, and the locally launched Chrome connects via loopback and is never blocked. IPv6 bind addresses are not supported.

`cdp-launch` uses Chrome DevTools Protocol and is the only mode that captures WebSocket frames, plus `resource_type` and cache/service-worker/body-size metadata, from Chrome's Network domain. The target sees Chrome's real TLS/HTTP behavior, but JavaScript automation signals may still be present. CDP modes do **not** capture Cookie/Set-Cookie on XHR/fetch (those are not exposed over CDP).

`cdp-attach` captures from an existing Chrome DevTools endpoint with the same capabilities and the same cookie limitation as `cdp-launch`.

Raw capture bundles persist until explicitly cleaned. Passive recon warns when local bundles are older than 30 days so you can review them with `apisniff bundles` and delete unneeded bundles with `apisniff clean`.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

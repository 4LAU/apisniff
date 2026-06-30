# apisniff CLI Specification

## Output Conventions

- Human summaries are written to stdout for interactive commands.
- `--json` enables machine-readable output where supported.
- `--output` / `-o` writes to a file where supported.
- Commands return a non-zero exit code on bad input, missing files, or network/capture failures.

## Flag Conventions

- Short flags use single letters where useful: `-i`, `-o`, `-f`, `-d`, `-H`.
- `--header` / `-H` accepts `key:value` and can be repeated.
- `probe --proxy` routes probe requests through an HTTP/SOCKS proxy.
- `recon` runs apisniff's local MITM proxy by default (`--mode proxy`); CDP modes are opt-in via `--mode cdp-launch` / `cdp-attach`. `recon --proxy` is reserved for future upstream proxy chaining.
- Replay sends only `GET`, `HEAD`, and `OPTIONS` by default. `--include-unsafe` opts into mutating methods.

## Bundle Layout

Bundles are created under `~/apisniff-captures/`:

```text
example-com_2026-05-12_14-30-00/
  flows.jsonl        -- captured HTTP flows (sensitive)
  session.json       -- capture metadata
```

Share output is derived and safe to review:

```text
share/
  openapi-spec.yaml
  inventory.json
  report.md
  session.json
```

Bundle directories are created owner-only.

## Safety Model

- `recon` and `analyze` can process full HTTP traffic, including credentials. Raw bundles must not be shared.
- `share` produces only derived artifacts and redacts cookie values.
- CDP capture preserves browser TLS/HTTP behavior but can still expose JavaScript automation signals.
- Proxy capture decrypts HTTPS via a local MITM CA. The default launched Chrome accepts the proxy certs through `--ignore-certificate-errors-spki-list` (nothing installed in any OS trust store). With `--no-browser`, trust `~/.apisniff/ca-cert.pem` only in clients/profiles you control. The CA private key (`~/.apisniff/ca-key.pem`) is sensitive — anything holding it can forge HTTPS certs for clients that trust the CA.
- `probe` and `replay` send real requests from your network.

## Supported Input Formats

| Format | Extension | Used by |
|--------|-----------|---------|
| JSONL | `.jsonl` | `analyze`, `spec`, `replay` |
| HAR | `.har` | `analyze`, `spec` |
| Burp XML | `.xml` | `analyze`, `spec` |

Format is auto-detected from file contents for `analyze` and `spec --input`.

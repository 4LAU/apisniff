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
- `recon --mode proxy` starts apisniff's local MITM proxy. `recon --proxy` is reserved for future upstream proxy chaining.
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
  spec.yaml
  inventory.json
  report.md
  session.json
```

Bundle directories are created owner-only.

## Safety Model

- `recon` and `analyze` can process full HTTP traffic, including credentials. Raw bundles must not be shared.
- `share` produces only derived artifacts and redacts cookie values.
- CDP capture preserves browser TLS/HTTP behavior but can still expose JavaScript automation signals.
- Proxy capture requires clients to trust `~/.apisniff/ca-cert.pem` for HTTPS MITM. Trust it only in clients/profiles you control.
- `probe` and `replay` send real requests from your network.

## Supported Input Formats

| Format | Extension | Used by |
|--------|-----------|---------|
| JSONL | `.jsonl` | `analyze`, `spec`, `replay` |
| HAR | `.har` | `analyze`, `spec` |
| Burp XML | `.xml` | `analyze`, `spec` |

Format is auto-detected from file contents for `analyze` and `spec --input`.

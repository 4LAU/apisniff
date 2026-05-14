# apisniff CLI Specification

## Output Conventions

All commands follow these rules:

- **Human output goes to stderr.** Status messages, progress indicators, warnings, and reports print to stderr via Rich. This keeps stdout clean for piping.
- **Data output goes to stdout.** When a command produces structured data (specs, JSON), it writes to stdout so it can be piped or redirected.
- **`--json` enables machine-readable output.** Every command that produces human output also accepts `--json` for structured JSON on stdout. The JSON schema is stable within a major version.
- **`--output` / `-o` writes to a file** instead of stdout, where supported.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Error (bad input, missing file, network failure) |
| `2`  | Full block (probe detected the target blocks all automated access) |

## Flag Conventions

- **Short flags** use single letters: `-i` (input), `-o` (output), `-f` (format), `-d` (domain), `-H` (header).
- **`--header` / `-H`** accepts `key:value` format. Can be repeated: `-H "Authorization:Bearer tok" -H "Accept:application/json"`.
- **`--proxy`** accepts `http://`, `https://`, `socks5://` URLs.
- **Common public flags** are for output, routing, credentials, and safety: `--json`, `--output`, `--format`, `--domain`, `--proxy`, `--header`, `--cookie-file`, `--dry-run`, `--include-unsafe`, and `--insecure`.
- **Opinionated defaults** do the useful thing without extra flags: `spec` includes redacted examples and formal security schemes by default.
- **Explicit network expansion** stays opt-in: `analyze --fetch-graphql` fetches GraphQL schemas from detected endpoints.
- **Opt-out flags** exist for the few defaults users may need to suppress, such as `--no-examples`.

## Bundle Layout

A bundle is a directory created by `recon` or `analyze`, stored under `~/apisniff-captures/`. Structure:

```
example-com_2026-05-12_14-30/
  flows.jsonl        — Captured HTTP flows (SENSITIVE — contains credentials)
  session.json       — Capture metadata (domain, duration, flow counts)
  cookies.txt        — Netscape cookie jar (SENSITIVE — session credentials)
  report.md          — Recon report (vendors, auth, endpoints)
  graphql-schema.json — GraphQL introspection result (if detected)
```

**Naming:** `{domain}_{date}_{time}` for recon, `{domain}_{date}_{time}_analyze` for analyze.

**Permissions:** Bundle directories and `~/apisniff-captures/` are created with `0o700` (owner-only).

## Safety Model

- **`recon` and `analyze` capture full HTTP traffic** including credentials. Raw bundles must never be shared.
- **`recon` uses mitmproxy for HTTPS capture.** The mitmproxy CA certificate lets the proxied browser trust locally generated certificates, which is what makes decrypted HTTPS inspection possible. Trust it only on machines and browser profiles you control.
- **`share` produces only derived artifacts.** No raw traffic, no cookie values, no headers. Output is safe to distribute.
- **`replay` defaults to safe methods only** (GET, HEAD, OPTIONS). `--include-unsafe` opts in to POST/PUT/DELETE/PATCH.
- **`apisniff probe rate` is opt-in** because it fires 20 rapid requests that may trigger rate limiting.
- **`probe` sends real HTTP requests from your IP.** Results reflect your IP's reputation. Use `--proxy` to test from different vantage points.

## Supported Input Formats

| Format | Extension | Used by |
|--------|-----------|---------|
| JSONL  | `.jsonl`  | `analyze`, `spec` (native format from `recon`) |
| HAR    | `.har`    | `analyze`, `spec` (Chrome DevTools, browser extensions) |
| Burp XML | `.xml` | `analyze` (Burp Suite export) |

Format is auto-detected from file contents, not extension.

## Shell Completion

Typer provides built-in shell completion:

```bash
# Install for your shell (bash, zsh, fish, powershell)
apisniff --install-completion

# Show completion script without installing
apisniff --show-completion
```

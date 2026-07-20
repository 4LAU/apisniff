---
name: apisniff
description: Use when capturing a website's API traffic, generating an OpenAPI spec from a real browser session, checking a captured API for drift, or working with apisniff capture bundles.
---

# apisniff

Capture real API traffic through a browser and turn it into an OpenAPI spec.

## Workflow

```bash
apisniff probe example.com      # what defends it?
apisniff recon example.com      # capture (needs a human — see below)
apisniff spec example.com -o openapi.yaml
apisniff replay example.com     # check for drift
```

`analyze` replaces `recon` when traffic already exists as HAR, Burp XML, or
JSONL. Bare `analyze` only prints a report — it writes no bundle, so a later
`apisniff spec example.com` would resolve some older bundle or none at all.
Either pass `--output-dir` to `analyze`, or skip it and feed the file straight
to `spec -i`.

## `--json` does not work on `spec`

The root help says to use `--json` on every command. That is wrong for `spec`,
which is the only command without a `--json` flag. `apisniff spec x --json`
exits with `unknown flag: --json`.

Use `-f json` for a JSON-formatted spec:

```bash
apisniff spec example.com -f json -o openapi.json
```

Every other command (`probe`, `recon`, `analyze`, `replay`, `share`, `bundles`,
`clean`) accepts `--json`.

## Flag contracts that fail at runtime

| Command | Contract |
|---|---|
| `analyze --fetch-graphql` | Requires `--output-dir`. Without it: `--fetch-graphql requires --output-dir to store the introspection result` |
| `share -o` | A **directory**, not a file. Defaults to `<bundle>/share` |
| `spec -o` | A file path |
| `spec -i` | Reads a HAR, Burp XML, or JSONL file directly — no need to run `analyze` first just to feed `spec`. The positional `DOMAIN` is **still required**: `apisniff spec example.com -i traffic.har`. Omitting it fails with `accepts 1 arg(s), received 0` |
| `spec --include-*` | Only work with `-i` on the original capture. Against a bundle they do nothing — `flows.jsonl` already excludes the filtered traffic, and apisniff prints `inclusion filters have no effect on pre-filtered bundles`. They only ever widen the spec — the default output is always still present. An unrecognized `--include-category` value is silently ignored, not rejected |
| `clean` | Non-interactive (any agent run) deletes nothing without `--yes` — it exits with `confirmation required; rerun with --yes or --dry-run`. Pair with `--dry-run` first |
| `spec -f` | `json` gives JSON; **every other value silently gives YAML**, including a typo. `-f jsno -o spec.json` exits 0 and writes YAML into a `.json` file |
| `replay --impersonate` | Only `chrome` or `firefox` |
| `probe --impersonate` | Accepted but **ignored** — the probe always uses the Chrome TLS profile. Passing `firefox` silently gives you Chrome results, so never report probe output as Firefox |

Run `apisniff <command> --help` for the full flag list. Everything above is the
part `--help` does not tell you.

## `recon` needs a person

`recon` opens a real Chrome and blocks until a human logs in by hand and closes
the window. There is no credential, cookie, or token flag — that is deliberate,
since the clean profile is what gets past bot detection.

Never fire `recon` and wait on it while running unattended. Hand that step to
the user, wait to be told it finished, then resume at `apisniff bundles`.

Everything else in the workflow runs unattended.

## Capture bundles hold live credentials

Bundles contain real session cookies. Never commit one, never paste flow
contents into a reply. `apisniff bundles --credentials` reports what a bundle
is carrying.

To hand a capture to someone else, use `share` — it exports the spec, a
redacted inventory, and a report, and excludes raw traffic and cookie values.

`replay` defaults to safe methods (`GET`, `HEAD`, `OPTIONS`) and strips captured
auth. `--include-unsafe` and `--forward-auth` undo those defaults: together they
re-fire captured writes with the original session, which can repeat real
state-changing calls. Ask before using either.

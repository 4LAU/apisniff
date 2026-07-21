# `apisniff spec`

Generate an OpenAPI 3.0.3 specification from captured traffic.

## Usage

```bash
apisniff spec BUNDLE|DOMAIN [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input`, `-i` | latest bundle | Input file: JSONL, HAR, or Burp XML |
| `--format`, `-f` | `yaml` | Output format: `yaml` or `json`. Anything else is treated as `yaml`, silently |
| `--json` | `false` | Shorthand for `--format json`. Cannot be combined with `--format` |
| `--output`, `-o` | stdout | Output file path |
| `--surface-output` | | Write the surface inventory (every candidate flow, plus the coverage report) as JSON to this path |
| `--include-third-party` | `false` | Also include flows classified `third_party_api` |
| `--include-category` | | Also include flows in this category, repeatable |
| `--include-host` | | Also include flows from this host, repeatable |
| `--infer-security-schemes` | `false` | Emit OpenAPI security schemes from observed auth |
| `--examples` | `false` | Include redacted examples |

## Examples

```bash
apisniff spec example.com
apisniff spec example.com -i capture.jsonl -f json -o spec.json
apisniff spec example.com -i traffic.har -o openapi-spec.yaml
apisniff spec example.com --infer-security-schemes --examples

# Widen the spec to cover third-party and telemetry traffic too
# (needs the original capture — see Inclusion filters below)
apisniff spec example.com -i traffic.har --include-third-party --include-category telemetry

# Pull in one specific host that was filtered out
apisniff spec example.com -i traffic.har --include-host api.cdn.example.com

# Write the inventory alongside the spec to see what was left out and why
apisniff spec example.com -o openapi.yaml --surface-output surface.json
```

## Inclusion filters

By default `spec` documents the target's own API and leaves out third-party
calls, telemetry, static assets, and other noise. The `--include-*` flags put
some of that back.

**They only work on the original capture, not on a bundle.** `recon` writes the
flows it kept to `flows.jsonl` and everything it filtered to `filtered.jsonl`,
and `spec` reads only `flows.jsonl` — so the excluded traffic is not in front of
the filters to re-include. Pointing `spec` at a bundle with an `--include-*`
flag prints `inclusion filters have no effect on pre-filtered bundles; pass the
original capture file via --input` and changes nothing. Pass the HAR, Burp XML,
or raw JSONL with `-i` instead.

**The flags only ever widen the spec.** Whatever `spec` emits by default is
always still there once you add an `--include-*` flag; the flag can only add to
it. So it is safe to try one without checking what it might displace.

`--include-category` only has anything to re-include from the categories the
classifier actually excludes: `third_party_api`, `telemetry`, `static`,
`antibot`, `options`. The categories it keeps — `business_api`, `auth`,
`unknown_api_like` — are already in the spec, so naming one adds nothing.
Values are case-insensitive and an optional `category:` prefix is allowed. An
unrecognized value is silently ignored rather than rejected, so a typo shows up
as a filter that quietly does nothing.

If filtering leaves nothing behind, `spec` fails with `no valid API flows after
filtering; adjust inclusion filters or capture API traffic: no valid API flows
for spec generation`. Run it again with `--surface-output` to get the inventory, which
lists every candidate flow and the category it was assigned, and shows what to
add back.

---

[All commands](../../README.md#commands) · [CLI spec](../spec.md)

# Workflow Recipes

Real tasks you can do with apisniff, start to finish.

## Map an API you've never seen before

```bash
# 1. Check defenses
apisniff probe api.example.com

# 2. If not blocked: capture traffic by browsing the site
apisniff recon example.com

# 3. Generate the API spec
apisniff spec example.com -o spec.yaml

# 4. See what you found
cat spec.yaml
```

If this is your first HTTPS capture, read the [mitmproxy certificate note](getting-started.md#https-and-the-mitmproxy-certificate) before browsing through `recon`.

## Check if an API has changed since your last capture

```bash
# Replay your captured requests against the live site
apisniff replay example.com

# See exactly which endpoints drifted
apisniff replay example.com --json -o drift.json
```

Replay compares response status codes, JSON structure, and body size. Each endpoint gets a verdict: **match** (unchanged), **drift** (something changed), **auth_expired** (credentials no longer work), or **blocked** (defenses are blocking you).

## Replay with saved credentials

After `recon`, apisniff saves a `cookies.txt` file in the bundle:

```bash
apisniff replay example.com \
  --cookie-file ~/apisniff-captures/example-com_2026-05-12/cookies.txt
```

You can also pass auth headers directly:

```bash
apisniff replay example.com -H "Authorization:Bearer your-token"
```

## Analyze a HAR file from Chrome DevTools

1. Open Chrome DevTools → Network tab
2. Browse the site
3. Right-click in the network list → "Save all as HAR with content"
4. Run:

```bash
apisniff analyze traffic.har
```

Same classification pipeline as recon, same bundle output with report.

## Analyze a Burp Suite capture

```bash
apisniff analyze burp-export.xml --domain api.example.com
```

Burp exports may contain traffic for many domains. Use `--domain` to focus on the target.

## Compare defenses across IP types

```bash
# From your home IP
apisniff probe example.com --json > home.json

# From a datacenter IP (via proxy)
apisniff probe example.com --proxy socks5://datacenter:1080 --json > dc.json

# Run an explicit rate-limit check
apisniff probe rate example.com --json > rate.json
```

Many sites apply stricter defenses to datacenter/cloud IPs than residential ones.

## Test rate limiting

```bash
apisniff probe rate example.com
```

Fires 20 requests in sequence and reports:
- Whether 429 (rate limit) responses appear, and after how many requests
- Median response time and whether it increases (silent throttling)

## Map a GraphQL API

If `probe` detects a GraphQL endpoint with introspection enabled:

```bash
# Probe will report GraphQL endpoints and fetch the schema automatically
apisniff probe api.example.com

# The schema is saved to ~/apisniff-captures/graphql-schema.json
```

If the endpoint requires auth, pass headers:

```bash
apisniff probe api.example.com -H "Authorization:Bearer tok" --cookie "session=abc"
```

## Generate a spec

```bash
apisniff spec example.com -o spec.yaml
```

Example values are included by default from captured responses. Secrets (bearer tokens, API keys, JWTs) are automatically redacted to `***REDACTED***`. Strings longer than 200 characters are truncated. Use `--no-examples` when you want schemas only.

## Share results with a teammate

```bash
apisniff share example.com -o ./for-teammate/
```

The shared directory contains only derived data: an OpenAPI spec, endpoint inventory, session stats, and a report with redacted cookie values. No raw traffic. Safe to email, upload, or commit to a repo.

## Preview replay targets without sending requests

```bash
apisniff replay example.com --dry-run
```

Lists every endpoint that would be replayed, without actually sending requests.

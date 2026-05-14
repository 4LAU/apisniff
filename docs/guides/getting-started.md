# Getting Started

This guide walks through a complete API reconnaissance workflow: install apisniff, probe a target's defenses, capture live traffic, generate an API spec, and share the results.

## Install

```bash
pip install apisniff
# or
pipx install apisniff
# or
uv tool install apisniff
```

Requires Python 3.12+. The `recon` command also requires [mitmproxy](https://mitmproxy.org/) (installed automatically as a dependency).

## Step 1: Probe the target

Before capturing traffic, check what defenses are in place:

```bash
apisniff probe example.com
```

This sends three requests with different client profiles and compares the responses. You'll see a verdict (no protection, client-dependent, JS challenge, or full block) and any detected vendor products.

The probe will identify proxies and CDNs. If you see "full block," try `--impersonate` to switch TLS profiles or `--proxy` to route through a different IP.

## Step 2: Capture traffic

```bash
apisniff recon example.com
```

A local proxy starts on port 8080 and Chrome opens automatically. Browse the site normally: click through pages, submit forms, use the features you want to map. Every request is captured and classified in real-time.

Press **Ctrl+C** when you're done browsing. apisniff will:
- Filter out noise (ads, analytics, tracking pixels, third-party domains)
- Detect authentication patterns (bearer tokens, API keys, session cookies)
- Extract cookies into a reusable cookie jar
- Identify vendor products from response headers
- Generate a recon report

Results are saved to `~/apisniff-captures/example-com_<timestamp>/`.

### Already have a capture?

If you have a HAR file from Chrome DevTools or a Burp Suite export:

```bash
apisniff analyze traffic.har
# or
apisniff analyze burp-export.xml
```

Same processing pipeline, different input source.

## Step 3: Generate an API spec

```bash
apisniff spec example.com
```

The command reads your latest capture and produces an OpenAPI 3.0.3 spec on stdout. It includes:
- Every observed endpoint, normalized (e.g., `/users/123` → `/users/{id}`)
- Request and response schemas inferred from captured data
- Query parameters merged across observations
- Detected authentication patterns

Save it to a file:

```bash
apisniff spec example.com -o spec.yaml
```

Include example values from the captured data (secrets are auto-redacted):

```bash
apisniff spec example.com --examples -o spec.yaml
```

## Step 4: Share results

Raw capture bundles contain credentials and should never be shared. To create a safe export:

```bash
apisniff share example.com
```

The output is a directory with derived artifacts only: an OpenAPI spec, endpoint inventory, session metadata, and a redacted report. No raw traffic, no cookies, no headers.

## What to do with the spec

```bash
# Generate a client library
openapi-generator generate -i spec.yaml -g python -o client/

# Import into Postman
# File → Import → select spec.yaml

# Feed to an LLM for client generation
cat spec.yaml | llm "write a Python client for this API"
```

## Next steps

- [Workflow recipes](workflows.md): "check for API drift," "map a GraphQL API," and more
- [Capture formats](capture-formats.md): HAR, Burp XML, and JSONL explained
- [Command reference](../commands/): full flag documentation for every command
- [CLI spec](../spec.md): output format contracts and conventions

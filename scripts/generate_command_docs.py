#!/usr/bin/env python3
"""Generate docs/commands/*.md from Typer CLI introspection.

Generated from apisniff CLI. Do not edit manually.
Re-run: uv run python scripts/generate_command_docs.py
"""
from __future__ import annotations

import subprocess
from pathlib import Path

COMMANDS = ["probe", "recon", "analyze", "replay", "spec", "share"]
DOCS_DIR = Path(__file__).parent.parent / "docs" / "commands"

PREAMBLE = """\
<!-- Generated from apisniff CLI. Do not edit manually. -->
<!-- Re-run: uv run python scripts/generate_command_docs.py -->

"""

DESCRIPTIONS = {
    "probe": (
        "Assess what defenses protect a URL before you capture traffic. "
        "Sends three parallel requests with different client profiles and classifies the "
        "differential response. Detects 25+ vendor products (Cloudflare, Akamai, DataDome, etc.)."
    ),
    "recon": (
        "Browse a site through a local mitmproxy, classify every request "
        "in real-time. Filters noise (ads, analytics, third-party), detects antibot JS, and "
        "writes classified flows to a bundle directory."
    ),
    "analyze": (
        "Import a traffic capture file (HAR, Burp XML, or JSONL), run the "
        "same classification pipeline as recon, and produce a full bundle with report."
    ),
    "replay": (
        "Replay captured API calls against the live site and detect drift. Compares response "
        "status, structure, and size. Categorizes each endpoint as match, drift, auth_expired, "
        "blocked, or error."
    ),
    "spec": (
        "Generate an OpenAPI 3.0.3 specification from captured traffic. Groups requests by "
        "normalized path, infers schemas from response bodies, merges across multiple "
        "observations, and detects auth patterns."
    ),
    "share": (
        "Export a shareable summary from a capture bundle. Produces only derived artifacts "
        "(spec, inventory, report, session metadata). No raw traffic, no credentials, no "
        "cookie values."
    ),
}

EXAMPLES = {
    "probe": """\
## Examples

```bash
# Quick defense check
apisniff probe example.com

# With JSON output for scripting
apisniff probe example.com --json

# Route through a proxy
apisniff probe example.com --proxy socks5://127.0.0.1:1080

# Include auth headers for authenticated endpoints
apisniff probe api.example.com -H "Authorization:Bearer tok123"

# Detect rate limiting (fires 20 rapid requests)
apisniff probe rate example.com
```
""",
    "recon": """\
## Examples

```bash
# Start capturing traffic for a domain
apisniff recon example.com

# Use a different local port
apisniff recon example.com --port 9090

# Route through an upstream proxy
apisniff recon example.com --proxy http://corporate-proxy:3128
```

Browse the site in the Chrome window that opens. Press **Ctrl+C** to stop capture.
""",
    "analyze": """\
## Examples

```bash
# Analyze a HAR file exported from Chrome DevTools
apisniff analyze traffic.har

# Analyze a Burp Suite export
apisniff analyze burp-export.xml

# Analyze a previous apisniff capture
apisniff analyze ~/apisniff-captures/example-com_2026-05-12/flows.jsonl

# Specify the domain explicitly
apisniff analyze traffic.har --domain api.example.com

# Write results to a specific directory
apisniff analyze traffic.har --output-dir ./my-analysis/

# Fetch GraphQL schemas from detected endpoints
apisniff analyze traffic.har --fetch-graphql
```
""",
    "replay": """\
## Examples

```bash
# Replay the latest capture for a domain
apisniff replay example.com

# Replay a specific bundle directory
apisniff replay ~/apisniff-captures/example-com_2026-05-12

# Preview which endpoints would be replayed
apisniff replay example.com --dry-run

# Filter to specific paths
apisniff replay example.com --filter "/api/v1/users*"

# Use saved cookies for authenticated endpoints
apisniff replay example.com --cookie-file ~/apisniff-captures/example-com_2026-05-12/cookies.txt

# Include POST/PUT/DELETE endpoints (use with care)
apisniff replay example.com --include-unsafe

# JSON output for scripting
apisniff replay example.com --json -o results.json
```
""",
    "spec": """\
## Examples

```bash
# Generate spec from latest capture (YAML to stdout)
apisniff spec example.com

# From a specific input file
apisniff spec example.com -i capture.jsonl

# JSON format
apisniff spec example.com -f json

# Write to file
apisniff spec example.com -o spec.yaml

# Omit example values from captured data
apisniff spec example.com --no-examples

# From a HAR file, JSON format
apisniff spec example.com -i traffic.har -f json -o spec.json
```
""",
    "share": """\
## Examples

```bash
# Share the latest capture for a domain
apisniff share example.com

# Share a specific bundle directory
apisniff share ~/apisniff-captures/example-com_2026-05-12

# Specify output directory
apisniff share example.com -o ./for-teammate/
```

### What's included

| File | Contents |
|------|----------|
| `spec.yaml` | OpenAPI 3.0.3 specification |
| `inventory.json` | Endpoint summary (method, path, status codes, counts) |
| `session.json` | Capture metadata (domain, duration, flow counts) |
| `report.md` | Recon report with redacted cookie values |
| `graphql-schema.json` | GraphQL schema (if captured) |

### What's excluded

Raw traffic (`flows.jsonl`), cookies (`cookies.txt`), request/response headers, query
parameter values. The output is intentionally non-replayable.
""",
}


def _capture_help(command: str) -> str:
    result = subprocess.run(
        ["uv", "run", "apisniff", command, "--help"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to capture help for '{command}': {result.stderr}"
        )
    return "\n".join(line.rstrip() for line in result.stdout.splitlines())


def _generate_page(command: str) -> str:
    help_text = _capture_help(command)
    description = DESCRIPTIONS.get(command, "")
    examples = EXAMPLES.get(command, "")

    lines = [
        PREAMBLE,
        f"# `apisniff {command}`\n",
        f"{description}\n",
        "## Usage\n",
        "```",
        help_text.strip(),
        "```\n",
    ]

    if examples:
        lines.append(examples)

    lines.append("---\n\n[All commands](../README.md#commands) · [CLI spec](../spec.md)\n")

    return "\n".join(lines)


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    for command in COMMANDS:
        page = _generate_page(command)
        out_path = DOCS_DIR / f"{command}.md"
        out_path.write_text(page)
        print(f"  Generated {out_path}")

    print(f"\n  {len(COMMANDS)} command pages written to {DOCS_DIR}/")


if __name__ == "__main__":
    main()

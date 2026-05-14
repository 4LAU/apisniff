# Capture Formats

apisniff can import traffic from three sources. Format is auto-detected from file contents, not the extension.

## JSONL (native format)

The format used by `apisniff recon`. Each line is a JSON object with base64-encoded request/response bodies.

```bash
apisniff analyze flows.jsonl
apisniff spec example.com -i flows.jsonl
```

JSONL files are pre-classified — they've already been through the noise filter. `analyze` skips the classification step for JSONL input.

## HAR (HTTP Archive)

The standard browser traffic export format. Exported from Chrome DevTools, Firefox, or browser extensions like "HTTP Archive Viewer."

**To export from Chrome:**
1. Open DevTools (F12) → Network tab
2. Browse the site
3. Right-click in the network list → "Save all as HAR with content"

```bash
apisniff analyze traffic.har
```

HAR files contain all traffic (ads, analytics, images). `analyze` runs the full 7-stage classifier to filter noise.

## Burp XML

Exported from Burp Suite's proxy history or site map.

**To export from Burp:**
1. Select items in Proxy → HTTP history
2. Right-click → "Save selected items"
3. Choose XML format

```bash
apisniff analyze burp-export.xml --domain api.example.com
```

Burp exports often contain traffic for many domains. Use `--domain` to focus on the target. If omitted, apisniff picks the most common domain automatically (and warns if the choice is ambiguous).

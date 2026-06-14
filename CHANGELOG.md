# Changelog

## [Unreleased]

## [0.5.1] — 2026-06-13

### Changed
- Proxy mode now ends the capture session when you close the launched Chrome's last window/tab, not only on full quit (⌘Q) or Ctrl+C. Detection watches the launched browser's own renderer processes — scoped to its PID, so other Chrome instances are untouched — and uses no CDP or page-visible hook.

## [0.5.0] — 2026-06-13

### Added
- `replay` command: replay captured API calls against live endpoints and detect drift (match/drift/auth_expired/blocked)
- `analyze` command: offline import and analysis for HAR, Burp Suite XML, and JSONL captures
- `share` command: export derived artifacts (spec, inventory, report) without raw traffic or credentials
- `--impersonate` flag on `probe` and `replay` for TLS client profile selection (chrome, safari, firefox)
- `--probe-rate` flag for rate limit detection via 429 responses and silent throttling
- `--infer-security-schemes` flag: promote observed auth patterns to formal OpenAPI `securitySchemes`
- `--examples` flag: include example values from captured data with auto-redaction
- Spec aggregation: query parameters, example values, form bodies, and multi-response merging
- Burp Suite XML import adapter
- GraphQL introspection download with schema sidecar file
- Auth fingerprinting and RFC 6265 cookie-jar export
- Recon session report with flow stats, detected vendors, auth patterns, cookies, and endpoint inventory
- Bundle directory permissions restricted to owner-only (0o700)
- Proxy mode launches a clean Chrome with no automation fingerprint (no `--enable-automation`, no CDP attachment; `navigator.webdriver` stays false), enabling manual login past bot-detection vendors (DataDome, PerimeterX, and similar) that block CDP-launched browsers
- Automatic macOS login-keychain trust of the proxy CA in proxy mode (one-time, no admin), removing Chrome's certificate warning; remove with `security delete-certificate -c "apisniff local MITM CA"`
- Documentation: CLI specification, auto-generated command reference, getting started guide, workflow recipes, and capture formats guide

### Changed
- `--mode proxy` now drives its launched browser via a plain process launch instead of Chrome DevTools Protocol, using a fresh disposable profile that is wiped on exit; end a session by quitting Chrome (⌘Q) or pressing Ctrl+C
- `--headless` now applies to proxy mode as well as `cdp-launch`
- stdout/stderr discipline: human-readable output goes to stderr, machine-readable data to stdout
- Classifier now returns a structured `ClassifyResult` with drop categories
- Bundle I/O extracted from `recon.py` into a dedicated `bundle` module
- Domain extraction replaced with `tldextract`

### Fixed
- Cookie values redacted in reports and `share` output (names and domains only)
- HAR adapter: base64-encoded bodies, timestamps, query strings, and multi-value headers
- Classifier query-string false positives
- Set-Cookie attribute pollution and multi-value header collapse

## [0.1.0] — 2026-05-08

### Added
- `probe` command: parallel differential defense probing with 25 vendor signatures
- `recon` command: mitmproxy-based traffic capture with 7-stage classification
- `spec` command: OpenAPI 3.x generation from captured traffic (JSONL or HAR input)
- Rich terminal rendering with screenshottable panels
- `--json` flag on all commands
- `--proxy` flag for routing through SOCKS5/HTTP proxies
- Community-extensible vendor signatures (`signatures/vendors.json`)
- HAR file import support

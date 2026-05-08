# Changelog

## [0.1.0] — 2026-05-08

### Added
- `probe` command — parallel differential defense probing with 25 vendor signatures
- `recon` command — mitmproxy-based traffic capture with 7-stage classification
- `spec` command — OpenAPI 3.x generation from captured traffic (JSONL or HAR input)
- Rich terminal rendering with screenshottable panels
- `--json` flag on all commands
- `--proxy` flag for routing through SOCKS5/HTTP proxies
- Community-extensible vendor signatures (`signatures/vendors.json`)
- HAR file import support

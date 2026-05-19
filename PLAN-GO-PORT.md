# apisniff Go Port — Complete Plan

## Background & Motivation

### Why this port exists

This port is motivated by a convergence of factors discovered during research into TLS fingerprinting and the anti-bot detection landscape:

1. **The TLS fingerprinting arms race is accelerating.** A February 2026 article ([foura.ai/blog/ja4-tls-broke-basic-scraper](https://foura.ai/blog/ja4-tls-broke-basic-scraper)) documents that JA4 fingerprinting now classifies bots at 98.6% accuracy from the TLS handshake alone — before any headers are read. Post-quantum TLS (X25519MLKEM768) adds another detection vector: 93% of real Chrome connections now include a 1,124-byte post-quantum key share that most scraping tools omit.

2. **Go is the natural language for this problem domain.** The tools that solve TLS fingerprinting natively — Surf (enetx/surf), uTLS — are written in Go. apisniff's Python version depends on curl-cffi for TLS-fingerprinted probing, which wraps a patched C library through FFI. A Go version gets TLS fingerprinting natively with zero foreign dependencies.

3. **Go produces superior distribution artifacts.** apisniff is a CLI tool distributed via Homebrew. Go compiles to a single static binary with instant startup, no runtime dependencies, and trivial cross-compilation. The current Python version requires pipx/virtualenv management.

4. **No equivalent tool exists in Go.** Research confirmed that no single Go project combines traffic interception + endpoint classification + OpenAPI generation + WAF/anti-bot detection + HAR/Burp import. The closest was Akita CLI (postmanlabs/observability-cli), which was sunsetted in March 2025 after Postman acquired the team and folded the tech into Postman Live Insights. apisniff-go would be unique in the Go ecosystem.

### The TLS fingerprinting landscape (context for implementer)

**What JA4 is:** JA4 creates a hash from the TLS ClientHello message — the very first thing a client sends when connecting. It captures protocol version, cipher suites, extensions, signature algorithms, and ALPN values. Unlike its predecessor JA3, JA4 sorts extensions before hashing, so randomizing extension order doesn't help evade detection.

**Why this matters for apisniff:** The `probe` command sends requests with different TLS fingerprints to detect whether a target uses bot detection. In Python, this relies on curl-cffi to impersonate Chrome/Firefox TLS. In Go, this becomes native via Surf or uTLS — a cleaner, faster, and more maintainable approach.

**Post-quantum TLS:** As of early 2026, Chrome includes an X25519MLKEM768 key share in its ClientHello by default. This balloons the ClientHello from ~400 bytes to ~1,400 bytes. Any tool claiming to be Chrome that omits this is immediately suspicious.

**Multi-layer detection:** TLS fingerprinting (JA3/JA4) is only one detection layer. Sophisticated systems like Akamai Bot Manager also fingerprint HTTP/2 SETTINGS frames, WINDOW_UPDATE behavior, pseudo-header ordering (:method, :authority, :scheme, :path), and header ordering. curl-cffi is constrained by libcurl's HTTP/2 implementation and has historically been weaker at this layer, which is why Impit (which forks the Rust h2 crate for full HTTP/2 frame control) and Surf (which controls HTTP/2 settings natively) have been observed to pass detection that curl-cffi fails against Akamai-protected targets.

### Key architectural insight: MITM capture contradicts the TLS fingerprinting thesis

The Python version's `recon` command captures traffic by running Chrome through a MITM proxy (mitmproxy). This means **the target server never sees Chrome's real TLS handshake** — it sees the proxy's handshake. The tool built to understand anti-bot detection is itself presenting an inauthentic TLS fingerprint during capture.

This is acceptable for mapping API surfaces when the target has no bot detection. But for targets with sophisticated detection (the exact scenario this tool is designed to analyze), MITM capture may trigger blocking and produce an incomplete or degraded view of the API surface.

**The Go port addresses this by making Chrome DevTools Protocol (CDP) the primary capture method for browser-based recon.** CDP observes traffic from inside Chrome without sitting in the network path. The target sees Chrome's authentic TLS handshake, HTTP/2 frames, and all behavioral signals. MITM proxy is retained as an optional mode for non-browser clients (mobile apps, CLI tools, arbitrary HTTP clients).

---

## Critical Decisions

### TLS Fingerprinting Library: Surf (enetx/surf)

#### Options evaluated

| Library | Language | Architecture | Latest Chrome | PQ TLS | HTTP/3 |
|---------|----------|-------------|---------------|--------|--------|
| **curl-cffi** | Python (C FFI) | Patched libcurl + BoringSSL | 146 | Not documented | Yes (partly paywalled) |
| **Impit** | Rust (Python/Node bindings) | Patched rustls | 142 | Yes (confirmed in Chrome 142 profile) | Experimental |
| **Surf** | Go (native) | uTLS | 145 | Yes (confirmed: X25519MLKEM768 in Chrome profiles) | Yes + QUIC fingerprinting |

#### Decision: Surf

**Rationale:**
- Native Go — no FFI bridge, no C dependencies, no subprocess overhead
- Closest to current Chrome (145 vs 148 current = 3 versions behind)
- Best HTTP/3 + QUIC fingerprinting support of any option
- Includes JA3, JA4, and JA4QUIC fingerprint profiles
- Post-quantum TLS confirmed: Chrome profiles include X25519MLKEM768 (verified in package source via Chrome145, Chrome120PQ, and SetHelloSpec)
- HTTP/2 SETTINGS frame fingerprinting (addresses the Akamai detection layer that curl-cffi struggles with)
- 200 releases in 9 months demonstrates active maintenance
- MIT licensed

**Risk: Solo developer.** Surf is maintained by one person (enetx) with no corporate backing. Mitigation: Surf's core dependency is uTLS (refraction-networking/utls), which is well-maintained by a larger team. If Surf stalls, uTLS can be used directly with more manual work.

**Fallback plan:** If Surf proves inadequate, use uTLS directly via refraction-networking/utls. This is more work (manual profile construction) but removes the Surf dependency entirely.

### Browser Capture: CDP-first, MITM as optional fallback

#### Why CDP is the primary capture mode

The `recon` command already launches Chrome specifically — it's a Chrome-only flow. CDP (Chrome DevTools Protocol) is a built-in channel inside Chrome that exposes all network traffic without sitting in the network path:

- `Network.requestWillBeSent` — fires before each request
- `Network.responseReceived` — fires when response headers arrive
- `Network.getResponseBody` — retrieves response body
- `Network.getRequestPostData` — retrieves POST body

**Advantages over MITM for browser recon:**
- Target sees Chrome's real TLS handshake (authentic JA3/JA4)
- Target sees Chrome's real HTTP/2 frames (authentic Akamai fingerprint)
- No CA certificate installation required
- No proxy configuration required
- Works with HTTPS without any decryption overhead
- Captures WebSocket, SSE, and streaming responses natively

**CDP detection considerations:** Anti-bot systems can detect CDP usage. Chrome definitely sets `navigator.webdriver = true` when launched with `--remote-debugging-port=0`; behavior with a fixed nonzero port is less documented and must be verified in Phase 0.2. Chrome 136+ also requires a non-default `--user-data-dir` for remote debugging, adding another fingerprint. These signals are detectable by anti-bot systems. The plan does not claim CDP is fully stealthy — it claims CDP preserves TLS/HTTP/2 authenticity, which is a separate (and more important) property than JavaScript-level stealth.

#### Why MITM is retained as a fallback

MITM proxy is not obsolete — it serves fundamentally different use cases:
- **Mobile app traffic:** CDP only works with Chrome. Capturing iOS/Android app traffic requires a proxy.
- **Non-browser clients:** CLI tools, desktop apps, custom HTTP clients.
- **Request modification:** Security researchers need to intercept and modify requests in flight. Burp Suite (a MITM proxy) remains the primary tool for penetration testing.
- **Protocol-level debugging:** When you need raw TLS/HTTP/2 frame data, not Chrome's parsed view.

The `recon` command supports three capture modes:

- **`apisniff recon DOMAIN --mode cdp-launch`** (default) — Launches Chrome with `--remote-debugging-port` and a dedicated user data dir. Convenient, no CA certificate needed. Target sees Chrome's real TLS/HTTP/2 fingerprint. Trade-off: `navigator.webdriver` may be set to `true` (confirmed for port 0; fixed nonzero port behavior must be verified in Phase 0.2) and a non-default profile directory is used, both of which are potentially detectable by JavaScript-level anti-bot checks. Best for: most targets, especially those without sophisticated JS-level bot detection.

- **`apisniff recon DOMAIN --mode cdp-attach`** — Attaches CDP to an already-running Chrome instance (user must start Chrome themselves with `--remote-debugging-port`). Best browser fidelity: the user controls the launch flags, profile directory, and can browse normally before attaching. Trade-off: requires manual Chrome setup. Best for: targets with aggressive anti-bot JS detection where you need maximum stealth.

- **`apisniff recon DOMAIN --mode proxy`** — MITM proxy mode. Launches Chrome routed through a local goproxy-based proxy. Captures traffic from any client, not just Chrome. Supports request modification. Trade-off: target sees the proxy's TLS fingerprint, not Chrome's. Triggers TLS-based bot detection. Best for: mobile app traffic, non-browser clients, or when you specifically want to see how the target responds to a non-browser TLS fingerprint.

#### MITM library: elazarl/goproxy

For the `--mode proxy` fallback:

| Library | Stars | Status | Capability |
|---------|-------|--------|-----------|
| **elazarl/goproxy** | 6,681 | Active (May 2026) | HTTP/HTTPS MITM, handler-based API, production-proven |
| **lqqyt2423/go-mitmproxy** | 1,514 | Active (Apr 2026) | Full mitmproxy-like tool: web UI, plugins, HTTP/2, WebSocket |
| **saucelabs/forwarder** | 279 | Active | Commercial-grade, HTTP/2, WebSocket, SSE, raw TCP |

**Decision: elazarl/goproxy.** Most established Go proxy library (13+ years, 6.6k stars). Clean handler-based API. Composes with standard `net/http`. Actively maintained. Used by Stripe, Winston Privacy, Forensant.

**Why not go-mitmproxy:** It's a standalone tool, not a library. We need to embed proxy functionality inside apisniff, not shell out to another tool.

---

## Go Dependency Mapping

Every Python dependency maps to a Go equivalent:

| Python Dependency | Purpose in apisniff | Go Equivalent |
|---|---|---|
| **mitmproxy** | HTTPS traffic interception | **chromedp/chromedp** (CDP, primary) + **elazarl/goproxy** (MITM, fallback) |
| **curl-cffi** | TLS-fingerprinted HTTP requests | **enetx/surf** (or direct uTLS) |
| **httpx** | Standard async HTTP client | **net/http** (stdlib) |
| **typer** | CLI framework | **spf13/cobra** |
| **rich** | Terminal rendering (tables, colors) | **charmbracelet/lipgloss** + **olekukonko/tablewriter** |
| **pyyaml** | YAML parsing/generation | **gopkg.in/yaml.v3** |
| **tldextract** | Public suffix domain extraction | **weppos/publicsuffix-go** or **joeguo/tldextract** |
| **defusedxml** | Safe XML parsing (Burp import) | **encoding/xml** (stdlib — Go's XML parser is safe by default, no external entity expansion) |
| **beautifulsoup4** | HTML parsing (not heavily used) | **PuerkitoBio/goquery** (if needed) |
| **pytest / hypothesis** | Testing | **testing** (stdlib) + **stretchr/testify** + **pgregory.net/rapid** (property-based) |

---

## Current Python Architecture (what we're porting)

```
apisniff (Python) — ~6,176 lines across 25 modules

CLI Layer (typer)
├── probe      → Dual-channel TLS probing + vendor detection
├── recon      → mitmproxy subprocess + classify + JSONL capture
├── analyze    → HAR/Burp/JSONL import + classify
├── replay     → Replay captured flows, detect drift
├── spec       → Generate OpenAPI 3.0.3 from captures
└── share      → Export safe artifacts (no credentials)

Core Logic
├── models.py       → Data types (CapturedFlow, ProbeResult, etc.)
├── probe.py        → Dual-channel probing (httpx + curl-cffi)
├── vendors.py      → 25+ vendor signature matching
├── classify.py     → 9-category traffic classification
├── surface.py      → API surface analysis
├── auth.py         → Auth pattern detection
├── spec.py         → OpenAPI generation
├── spec_schema.py  → JSON schema inference
├── spec_classify.py → Spec-specific classification
├── replay.py       → Flow replay + diff detection
├── bundle.py       → Capture bundle management
├── report.py       → Markdown report generation
├── share.py        → Safe export with redaction
└── proxy.py        → mitmproxy addon

Adapters
├── har.py          → HAR file parsing
├── burp.py         → Burp Suite XML parsing
└── mitmproxy_adapter.py → mitmproxy flow conversion

Output Rendering
├── probe.py        → Probe result tables
├── recon.py        → Session progress + stats
└── replay.py       → Drift detection display

Signatures
└── vendors.json    → 25+ vendor detection signatures
```

## Target Go Architecture

```
apisniff-go/
├── cmd/
│   └── apisniff/
│       └── main.go              → Entry point
├── internal/
│   ├── cli/                     → Cobra command definitions
│   │   ├── root.go
│   │   ├── probe.go
│   │   ├── recon.go
│   │   ├── analyze.go
│   │   ├── replay.go
│   │   ├── spec.go
│   │   └── share.go
│   ├── model/                   → Data types
│   │   ├── flow.go              → CapturedFlow
│   │   ├── probe.go             → ProbeResult, ProbeAssessment, ProbeVerdict
│   │   ├── vendor.go            → VendorMatch, VendorSignature
│   │   ├── classify.go          → ClassifyResult, SurfaceCategory
│   │   ├── session.go           → SessionStats
│   │   ├── replay.go            → ReplayResult
│   │   └── spec.go              → Spec-related types
│   ├── probe/                   → Probing engine
│   │   ├── prober.go            → Dual-channel probe orchestration
│   │   ├── surf_probe.go        → Surf-based TLS-fingerprinted probe
│   │   ├── raw_probe.go         → Standard net/http probe
│   │   ├── graphql.go           → GraphQL endpoint + introspection detection
│   │   └── ratelimit.go         → Rate limit detection
│   ├── vendor/                  → Vendor detection
│   │   ├── detector.go          → Signature matching engine
│   │   └── signatures.go        → Embedded vendor signatures (via //go:embed)
│   ├── classify/                → Traffic classification
│   │   ├── classifier.go        → 9-category classification engine
│   │   ├── surface.go           → API surface analysis
│   │   └── context.go           → Dynamic context learning (CSP, Referer)
│   ├── auth/                    → Auth pattern detection
│   │   └── detector.go          → Bearer, Basic, API key, session, token endpoint
│   ├── capture/                 → Traffic capture (both modes)
│   │   ├── cdp.go               → CDP-based Chrome capture (primary for recon)
│   │   ├── proxy.go             → goproxy-based MITM capture (--mode proxy)
│   │   ├── browser.go           → Chrome discovery + launch
│   │   ├── writer.go            → Atomic JSONL streaming writer
│   │   └── session.go           → Capture session management
│   ├── adapter/                 → Import adapters
│   │   ├── har.go               → HAR file parsing
│   │   ├── burp.go              → Burp Suite XML parsing
│   │   ├── jsonl.go             → Native JSONL loading
│   │   └── detect.go            → Format auto-detection
│   ├── spec/                    → OpenAPI generation
│   │   ├── generator.go         → OpenAPI 3.0.3 generation orchestration
│   │   ├── schema.go            → JSON schema inference (recursive, depth-limited)
│   │   ├── normalize.go         → Path normalization (UUIDs, IDs → parameters)
│   │   ├── security.go          → Security scheme inference
│   │   └── merge.go             → Schema merging across observations
│   ├── replay/                  → Flow replay
│   │   ├── replayer.go          → Replay engine with Surf for TLS fingerprinting
│   │   ├── diff.go              → Status + body shape comparison
│   │   └── cookies.go           → Netscape cookies.txt parser
│   ├── report/                  → Report generation
│   │   ├── markdown.go          → Markdown report
│   │   └── share.go             → Safe export with credential redaction
│   ├── bundle/                  → Capture bundle management
│   │   └── bundle.go            → Find, create, list capture bundles
│   └── output/                  → Terminal rendering
│       ├── probe.go             → Probe result tables
│       ├── recon.go             → Session progress display
│       └── replay.go            → Drift detection display
├── testdata/
│   └── golden/                  → Golden fixtures from Python version
│       ├── probe/               → Expected probe outputs per target
│       ├── classify/            → Expected classifications per flow set
│       ├── spec/                → Expected OpenAPI specs per capture
│       └── replay/              → Expected replay results
├── signatures/
│   └── vendors.json             → Vendor detection signatures (embedded via go:embed)
├── go.mod
├── go.sum
└── README.md
```

---

## Phased Implementation (risk-first ordering)

The plan is ordered by risk, not dependency. The hardest and most uncertain pieces come first. Stable business logic (classification, spec generation, adapters) is ported later, driven by golden fixtures from the Python version.

### Prerequisites: Golden Fixture Generation

**Before writing any Go code**, generate golden test fixtures from the Python version:

1. **Probe fixtures:** Run `apisniff probe` against 10-20 targets with varying protection levels (unprotected, Cloudflare, Akamai, DataDome, Imperva). Save the full ProbeAssessment JSON output for each. **Important:** These are reference snapshots, not strict contracts. Anti-bot responses drift by time, IP, geography, cookies, rate limits, and vendor rollout. Probe fixture tests use tolerant matching: verdict family (blocked vs. passed), vendor signal class (detected Cloudflare vs. not), and probe variant ordering — not byte-for-byte JSON parity. The goal is "same diagnostic conclusions," not "same bytes."

2. **Classification fixtures:** Take 3-5 existing capture bundles (flows.jsonl). Run classification on each and save the per-flow ClassifyResult as JSON. **These are strict contracts** — classification is deterministic logic over static input. Byte-for-byte parity expected.

3. **Spec fixtures:** Generate OpenAPI specs from the same captures. Save the YAML output. **Strict contracts** — deterministic transform over static input.

4. **Replay fixtures:** Run replay against saved bundles. Save ReplayResult JSON. **Reference snapshots with tolerant matching** (same as probe — live network responses are inherently non-deterministic).

5. **Adapter fixtures:** Collect sample HAR files, Burp XML exports, and JSONL captures. Save the parsed CapturedFlow output for each. **Strict contracts** — deterministic parsing of static files.

**Two tiers of golden tests:**
- **Strict (classification, spec, adapters):** Deterministic logic over static input. Byte-for-byte parity required. Regressions are bugs.
- **Tolerant (probe, replay):** Live network behavior. Match on verdict family, vendor class, and structural shape. Regressions are investigated, not automatically failed.

### Phase 0: Spike — Prove the Risky Primitives

**Goal:** Answer three questions with working code before committing to the full port. Each spike is a standalone `main.go` that proves or disproves a critical assumption.

#### Spike 0.1: Can Surf produce the browser fingerprints we need?

Build a minimal Go program that:
1. Uses Surf to make a request to a TLS fingerprint echo service (e.g., tls.peet.ws)
2. Captures the JA3 and JA4 hashes produced
3. Compares them against known Chrome 145 hashes
4. Verifies the X25519MLKEM768 post-quantum key share is present in the ClientHello
5. Makes the same request to 3-5 real targets with known bot detection (Cloudflare, Akamai, DataDome)
6. Compares pass/block results against curl-cffi and Impit hitting the same targets

**Pass criteria:** Surf's Chrome profile produces authentic JA3/JA4 hashes and passes detection on targets where curl-cffi or Impit also pass. PQ key share is confirmed present.

**This spike is likely to pass.** Surf's source confirms X25519MLKEM768 in Chrome profiles (Chrome145, Chrome120PQ, SetHelloSpec). But verify with live traffic before proceeding.

#### Spike 0.2: Does CDP-based capture produce usable flow data?

Build a minimal Go program using `chromedp/chromedp` that:
1. Launches Chrome (or attaches to a running instance)
2. Enables Network domain events (Network.enable)
3. Navigates to a target URL
4. Captures all network requests/responses via Network.requestWillBeSent, Network.responseReceived, Network.getResponseBody, Network.getRequestPostData
5. Converts captured events into the CapturedFlow JSONL format (same schema as Python version)
6. Compares the captured flows against what the Python mitmproxy-based recon produces for the same target

**Key questions this spike answers:**
- Does CDP capture all user-relevant API candidate requests needed by the classifier and spec generator? (Not "same count as mitmproxy" — CDP may capture more or fewer requests, and that's fine as long as the API surface is complete)
- Response body retrieval: what fails? Test by size (1KB, 1MB, 10MB, 100MB), type (JSON, binary, streaming), cache status (cached vs. fresh), and service worker interception. Document the gaps.
- `navigator.webdriver` behavior: test under three configurations: (a) `--remote-debugging-port=0` with default profile, (b) fixed random port with dedicated `--user-data-dir`, (c) attaching to user-launched Chrome. Document which configurations expose automation signals.
- Chrome 136+ behavior: verify that `--remote-debugging-port` requires a non-default `--user-data-dir` and test the fallback behavior.
- WebSocket and SSE: verify `Network.webSocketFrameReceived`, `Network.webSocketFrameSent`, and `Network.eventSourceMessageReceived` produce usable data.

**Pass criteria:** CDP captures all API-candidate requests needed to produce a useful OpenAPI spec from the same browsing session. Known gaps (e.g., large binary response bodies, service-worker-intercepted requests) are documented with workarounds. The produced flows.jsonl generates the same useful spec, not necessarily the same raw request count.

#### Spike 0.3: Can golden fixtures drive the port?

Build a minimal Go program that:
1. Loads a golden classification fixture (from Prerequisites)
2. Loads the corresponding flows.jsonl
3. Runs a stub classifier that returns hardcoded results
4. Compares against the golden output using a diff

This validates the testing harness and fixture format before porting real logic.

**Pass criteria:** The fixture loading, comparison, and diff reporting works end-to-end.

#### Phase 0 Decision Gate

If all three spikes pass → proceed to Phase 1.
If Spike 0.1 fails → evaluate uTLS directly, or reconsider Surf vs. alternatives.
If Spike 0.2 fails → fall back to MITM-first architecture (goproxy as primary).
If Spike 0.3 fails → fix the fixture format or test harness before proceeding.

### Phase 1: Vertical Slice — End-to-End Proof

**Goal:** Three commands work end-to-end, proving Go is better at the parts that matter.

#### 1.1 Data Models (`internal/model/`)

Port all types from Python `models.py`:

- **CapturedFlow** — Immutable HTTP request/response. Fields: Method, Host, Path, URL, RequestHeaders (map[string]string), RequestBody ([]byte), ResponseStatus (int), ResponseHeaders, ResponseBody, BodyEncoding, Tags ([]string), Timestamp (float64). Include JSON serialization tags for JSONL compatibility. Base64 encode/decode bodies for JSONL format.
- **ProbeResult** — Single probe outcome: Variant (string), Status (int), Latency (time.Duration), Headers (map[string]string), Body ([]byte), Error (error)
- **ProbeAssessment** — Aggregated: Verdict (ProbeVerdict), Vendors ([]VendorMatch), GraphQL (*GraphQLResult), RateLimit (*RateLimitResult)
- **ProbeVerdict** — Enum via iota: NO_PROTECTION, CLIENT_DEPENDENT, JS_CHALLENGE, FULL_BLOCK
- **VendorMatch** — Vendor (string), Confidence (string: high/medium/low), Signals ([]string)
- **ClassifyResult** — Action (keep/drop), Category (SurfaceCategory), Reason (string), APILike (bool), HostRole (string), Signals ([]string)
- **SurfaceCategory** — Enum: business_api, auth, antibot, captcha, telemetry, third_party_api, static, non_api, unknown_api_like, options
- **SessionStats** — Domain, StartedAt, Duration, TotalFlows, KeptFlows, etc.
- **ReplayResult** — Outcome enum (match/drift/auth_expired/blocked/error) + details

Port utility functions:
- `GetHeader()` — case-insensitive header lookup
- `NormalizePath()` — UUID/numeric segments → `{id}`
- `IsDynamicSegment()` — detect UUID/numeric path segments
- `ReplayDedupKey()` — stable dedup key

#### 1.2 CLI Skeleton (`internal/cli/`)

Use **spf13/cobra** to define all 6 commands with their flags:

```
apisniff probe [URL | rate URL]
  --json, --proxy, --header, --cookie, --insecure, --impersonate

apisniff recon DOMAIN
  --json, --proxy, --port (default 8080),
  --mode (cdp-launch|cdp-attach|proxy, default cdp-launch)

apisniff analyze INPUT_FILE
  --domain, --json, --output-dir, --fetch-graphql

apisniff replay BUNDLE|DOMAIN
  --filter, --timeout, --cookie-file, --header, --json, --output, --dry-run,
  --include-unsafe, --insecure, --impersonate

apisniff spec DOMAIN
  --input, --format (yaml/json), --output, --surface-output,
  --include-third-party, --include-category, --include-host,
  --no-infer-security-schemes, --examples

apisniff share BUNDLE|DOMAIN
  --output, --domain
```

Note the new `--mode` flag on `recon`: `cdp-launch` (default), `cdp-attach`, or `proxy`.

#### 1.3 Probe Command (full implementation)

**Vendor Detection (`internal/vendor/`):**
- Embed `vendors.json` using `//go:embed`
- Compile regex patterns at init time (verify all patterns are RE2-compatible — Go's `regexp` uses RE2, no backreferences or lookaheads)
- Match function: takes response headers, cookies, body, status → returns []VendorMatch with confidence scoring
- 25+ vendors: Cloudflare, Akamai, DataDome, PerimeterX, Imperva, Kasada, Shape Security, reCAPTCHA, hCaptcha, Arkose, Geetest, Turnstile, AWS WAF, F5 BigIP, Sucuri, Reblaze, Cheq, LinkedIn, Reddit
- Signal types: header presence/value/regex, cookie name patterns, body contains, status codes
- Confidence: high (2+ signals), medium (1-2), low (>0)

**Raw Probe (`internal/probe/raw_probe.go`):**
Standard `net/http` client probe with bot User-Agent. Configurable timeout, proxy, TLS verification, redirect following.

**Surf Probe (`internal/probe/surf_probe.go`):**
Surf-based TLS-fingerprinted probe. Three profiles:
- Chrome (Windows) — primary
- Chrome (macOS) — secondary
- Firefox — tertiary

Each probe variant:
- "naked": raw net/http + bot UA
- "impersonated": Surf Chrome TLS + Chrome UA
- "tls_only": Surf Chrome TLS + bot UA

**GraphQL Detection (`internal/probe/graphql.go`):**
- Probe common GraphQL paths: /graphql, /api/graphql, /gql, /query
- Test introspection query if endpoint found

**Rate Limit Detection (`internal/probe/ratelimit.go`):**
- Send 20 rapid requests to target
- Detect 429 status codes, Retry-After headers

**Probe Orchestration (`internal/probe/prober.go`):**
- Run all probe variants concurrently (goroutines)
- Collect results, determine verdict
- Vendor detection on each response

**Probe Output (`internal/output/probe.go`):**
Terminal tables + `--json` mode.

**Validate against golden probe fixtures.**

#### 1.4 Recon with CDP (vertical slice)

**CDP Capture (`internal/capture/cdp.go`):**
- Use `chromedp/chromedp` to connect to Chrome
- Enable Network domain (Network.enable with maxTotalBufferSize and maxResourceBufferSize configured for large payloads)
- Listen for Network.requestWillBeSent, Network.responseReceived
- Retrieve bodies via Network.getResponseBody, Network.getRequestPostData
- Handle body retrieval failures gracefully (large binaries, cached responses, service worker interceptions — log the gap, don't crash)
- WebSocket capture via Network.webSocketFrameReceived / webSocketFrameSent
- Convert CDP events → CapturedFlow
- Classify each flow (using stub classifier initially, real classifier when Phase 2 completes)
- Write kept flows to JSONL

**Browser Launch (`internal/capture/browser.go`):**
- Find Chrome/Chromium binary on macOS/Linux/Windows
- Three launch/attach modes:
  - **cdp-launch:** Start Chrome with a fixed random nonzero port (`--remote-debugging-port=PORT`) and a dedicated profile directory (`--user-data-dir=~/.apisniff/chrome-profile`). Required for Chrome 136+ compatibility. Note: this may set `navigator.webdriver = true` (confirmed for port 0; fixed nonzero port behavior to be verified in Phase 0.2) — document findings honestly in CLI help.
  - **cdp-attach:** Connect to a user-launched Chrome instance. User is responsible for starting Chrome with `--remote-debugging-port=PORT`. Best fidelity — no automation signals unless the user added them.
  - **proxy:** Launch Chrome with `--proxy-server=http://127.0.0.1:PORT`. No CDP involvement.

**JSONL Writer (`internal/capture/writer.go`):**
- Atomic writes (write to temp file, rename)
- File permissions 0o600
- Base64-encode request/response bodies
- Streaming — no buffering entire capture

**Session Management (`internal/capture/session.go`):**
- Create capture directory: `~/apisniff-captures/{domain}_{timestamp}/`
- Write session.json metadata on completion

#### 1.5 Analyze with golden fixtures

**Adapter for JSONL only** (simplest adapter first):
- Stream-parse native JSONL format
- Validate against golden fixtures

**Pass criteria for Phase 1:** `apisniff-go probe URL` produces results matching Python golden fixtures (tolerant: verdict family + vendor class). `apisniff-go recon DOMAIN` (cdp-launch mode) captures traffic and writes valid JSONL. `apisniff-go analyze` loads JSONL and produces flow objects.

### Phase 2: Classification Engine

**Goal:** The classification engine produces identical results to the Python version for all golden fixtures.

#### 2.1 Traffic Classification (`internal/classify/`)

Port the full 9-category classification engine from `classify.py`:

**Classification decision tree (must be preserved exactly):**
1. Method = OPTIONS → drop (CORS preflight)
2. Path/host patterns → captcha detection (reCAPTCHA, hCaptcha, Arkose, Geetest, Turnstile domains)
3. Path/host/payload patterns → antibot detection (DataDome, PerimeterX, Kasada sensor URLs)
4. Path/host patterns → telemetry (analytics subdomains, beacon paths, noise domains)
5. Response content-type → static file detection (image/*, font/*, text/css, application/javascript, etc.)
6. API-likeness detection: JSON content-type, path patterns (/api/, /v1/), body shape, non-GET method
7. Auth path detection (/auth, /login, /token, /oauth, /signup, /register, etc.)
8. Host role (target/same_site/third_party) + api_like → final category assignment

**Dynamic context learning:**
- Parse CSP headers to discover related domains
- Track Referer/Origin headers for same-site relationships
- Classifier maintains learned state across flow stream

#### 2.2 Auth Detection (`internal/auth/detector.go`)

- Bearer tokens (Authorization: Bearer)
- Basic auth (Authorization: Basic)
- API key headers (X-API-Key, API-Key, APIKey)
- API key query params (api_key, apikey, key)
- Session cookies (session, sessionid, sid, jsessionid, phpsessid, connect.sid, laravel_session)
- Token endpoints (/oauth/token, /auth/token, /token)
- Cookie extraction from Set-Cookie headers with domain/path/secure tracking

**Validate against golden classification fixtures.**

### Phase 3: OpenAPI Spec Generation

**Goal:** `apisniff spec DOMAIN` produces specs matching Python golden fixtures.

#### 3.1 Flow Selection

- Default: target domain + business_api/auth categories
- `--include-third-party`: add third_party_api flows
- `--include-category`: repeatable category inclusion
- `--include-host`: repeatable host inclusion

#### 3.2 Path Normalization (`internal/spec/normalize.go`)

- UUIDs → `{id}` (regex: 8-4-4-4-12 hex pattern)
- Hex strings (12+ chars) → `{id}`
- Pure numeric segments → `{id}`
- Singularize parent segment for parameter name: `/users/123` → `/users/{userId}`
- Dedup parameter naming across paths

#### 3.3 Schema Inference (`internal/spec/schema.go`)

- Recursive JSON body → OpenAPI schema
- Type detection: string, integer, number, boolean, array, object
- Depth limit: 20 levels
- Sensitive field redaction: password, api_key, token, secret, authorization, credential, ssn, etc.
- Form URL-encoded body parsing
- Multipart form extraction (field names only, bodies redacted)
- File field detection
- Optional example inclusion

#### 3.4 Schema Merging (`internal/spec/merge.go`)

- Merge schemas across multiple observations of same endpoint
- Union types when observations disagree
- Preserve all observed properties

#### 3.5 Security Scheme Inference (`internal/spec/security.go`)

- Detect from auth patterns: Bearer → bearerAuth, Basic → basicAuth
- API key headers → apiKeyAuth
- Session cookies → cookieAuth

#### 3.6 Generator Orchestration (`internal/spec/generator.go`)

- Group flows by (method, normalized_path)
- Collect query parameters, request/response schemas per status code
- Generate OpenAPI 3.0.3 document
- Output YAML (default) or JSON

**Validate against golden spec fixtures.**

### Phase 4: Import Adapters

**Goal:** `apisniff analyze FILE` handles HAR, Burp XML, and JSONL.

#### 4.1 Format Detection (`internal/adapter/detect.go`)

Read first 1KB of file, detect format:
- HAR: JSON with `"log"` key containing `"entries"`
- Burp: XML with `<items>` root
- JSONL: Lines of JSON with `"method"` field

#### 4.2 HAR Adapter (`internal/adapter/har.go`)

- Parse HAR JSON structure (log → entries → request/response)
- Extract method, URL, headers, body
- Handle base64-encoded bodies
- Parse ISO 8601 timestamps

#### 4.3 Burp Adapter (`internal/adapter/burp.go`)

- Parse Burp Suite XML (items → item)
- Split raw HTTP messages into headers/body
- Handle base64 detection per element
- Use `encoding/xml` (safe by default in Go)

**Validate against golden adapter fixtures.**

### Phase 5: Replay Command

**Goal:** `apisniff replay BUNDLE` detects API drift.

#### 5.1 Flow Selection

- By glob pattern (`--filter`)
- Safe methods only by default (GET, HEAD, OPTIONS)
- `--include-unsafe` to allow POST/PUT/DELETE

#### 5.2 Cookie Handling (`internal/replay/cookies.go`)

- Parse Netscape cookies.txt format
- Domain/path matching for cookie injection

#### 5.3 Request Preparation

- Remove hop-by-hop headers (Connection, Keep-Alive, etc.)
- Optional auth header injection
- Query string preservation
- Use Surf for TLS-fingerprinted replay

#### 5.4 Diff Detection (`internal/replay/diff.go`)

- Status code comparison
- Body shape comparison (recursive JSON diff, depth 3)
- Response size tracking
- Categories: match, drift, auth_expired, blocked, error

**Validate against golden replay fixtures.**

### Phase 6: Share + Report + MITM Proxy Mode

**Goal:** Complete feature parity.

#### 6.1 Safe Export (`internal/report/share.go`)

- Copy only derived artifacts: spec.yaml, inventory.json, report.md, session.json
- Redact cookie values as "[redacted]"
- Strip raw traffic and credentials

#### 6.2 Markdown Report (`internal/report/markdown.go`)

- Flow statistics, vendor detection, auth patterns, cookie summary
- Top endpoints by frequency, surface category breakdown

#### 6.3 MITM Proxy Mode (`internal/capture/proxy.go`)

Build on goproxy for the `--mode proxy` fallback:
- Start HTTPS MITM proxy on configurable port (default 8080)
- Generate CA certificate at `~/.apisniff/ca-cert.pem`
- On each response: convert to CapturedFlow → classify → write kept flows to JSONL
- Track stats, handle SIGINT for graceful shutdown

---

## Testing Strategy

### Golden Fixture Tests (primary)

Every module is tested against golden outputs from the Python version. This is the primary correctness mechanism.

### Unit Tests

- **Vendor detection:** All 25+ vendor signatures against mock responses
- **Classification:** All 9 categories with representative flows
- **Path normalization:** UUIDs, hex strings, numeric IDs, edge cases
- **Schema inference:** JSON types, nested objects, arrays, sensitive field redaction
- **HAR/Burp parsing:** Real-world sample files
- **Replay diff:** Status match, body shape drift, auth expiry
- **Auth detection:** All pattern types

### Integration Tests

- **Probe:** Against a local test server with known fingerprint behavior
- **CDP capture:** Launch Chrome, navigate, verify JSONL output matches expected flows
- **MITM capture:** Start proxy, make requests, verify JSONL output
- **Spec generation:** Full pipeline from captured flows to OpenAPI, validate spec

### Property-Based Tests

Port Hypothesis-based tests from Python to Go using `pgregory.net/rapid`:
- Schema merging commutativity
- Path normalization idempotency
- Classification determinism

---

## Distribution

### Homebrew

The existing Homebrew tap at `4lau/tap` already distributes apisniff. The Go version simplifies this dramatically:

- **Before (Python):** Formula installs Python 3.12, Rust (for curl-cffi build), and 8+ Python dependencies. Complex build process.
- **After (Go):** Formula downloads a single pre-compiled binary. No runtime dependencies. Cross-compiled for darwin-arm64, darwin-amd64, linux-amd64, linux-arm64.

### GitHub Releases

Use GoReleaser to automate:
- Cross-compilation for all target platforms
- GitHub Release with checksums
- Homebrew formula auto-update

---

## Migration Path

### Step 1: Parallel development
Build apisniff-go as a new repo (or new branch). Keep Python apisniff working.

### Step 2: Feature parity verification
Run both versions against the same targets. Diff outputs using the two-tier model:
- **Strict parity (deterministic transforms):** Traffic classification categories, OpenAPI spec generation, adapter parsing — must produce identical output for identical input
- **Tolerant parity (live network behavior):** Probe verdicts and vendor detection, replay drift detection — must agree on verdict family and vendor signal class, not byte-for-byte

### Step 3: Switchover
Update Homebrew formula to point to Go binary. Archive Python version.

---

## Open Questions for Implementer

1. **Vendor signatures regex compatibility:** The current vendors.json uses Python regex syntax. Verify all patterns are compatible with Go's `regexp` package (RE2 syntax — no backreferences, no lookaheads). Port any incompatible patterns.

2. **CDP response body limits:** Chrome's CDP has limits on response body retrieval (large responses may be truncated). Determine the practical limit and whether `Network.streamResourceContent` is needed for large payloads.

3. **CDP WebSocket capture:** Verify that CDP's `Network.webSocketFrameReceived` and `Network.webSocketFrameSent` events capture WebSocket traffic reliably. The Python mitmproxy version handles WebSocket; the CDP version must too.

4. **CA certificate handling (proxy mode):** Should apisniff-go use its own CA (at ~/.apisniff/) or reuse mitmproxy's CA (at ~/.mitmproxy/) for users migrating from the Python version?

5. **Browser launch modes:** Support three modes: (a) launch new Chrome with CDP, (b) attach to existing Chrome via CDP, (c) launch Chrome with proxy. Consider `--no-browser` for users configuring their own client in proxy mode.

6. **goproxy HTTP/2 support:** goproxy handles HTTP/1.1 MITM well. Verify HTTP/2 interception works correctly for the `--mode proxy` path. This is less critical than in the original plan since MITM is now the fallback, not the primary mode.

---

## Existing Go Ecosystem (reference for implementer)

These existing Go projects may be useful as reference implementations or direct dependencies:

| Project | Relevance |
|---------|-----------|
| **enetx/surf** | TLS-fingerprinted HTTP requests (primary dependency for probe + replay) |
| **chromedp/chromedp** | CDP-based Chrome automation (primary dependency for recon) |
| **elazarl/goproxy** | MITM proxy engine (dependency for --mode proxy) |
| **spf13/cobra** | CLI framework (primary dependency) |
| **postmanlabs/observability-cli** (Akita, archived) | Reference for Go-based API traffic capture + OpenAPI generation |
| **dstotijn/hetty** | Reference for Go-based Burp alternative with MITM proxy |
| **projectdiscovery/proxify** | Reference for Go proxy with traffic capture |
| **ahmedtouahria/waf-detector** | Reference for Go-based WAF detection (YAML signatures) |
| **mrichman/hargo** | Reference for Go HAR parsing |
| **lair-framework/go-burp** | Reference for Go Burp XML parsing |
| **charmbracelet/lipgloss** | Terminal rendering (tables, colors) |
| **weppos/publicsuffix-go** | Public suffix / TLD extraction |

---

## Key Metrics for Success

1. **Probe accuracy parity:** Same verdict family and vendor signal class as Python version against a test suite of 20+ targets (tolerant matching — not byte-for-byte)
2. **Classification parity:** Identical category assignments for identical traffic captures (strict golden fixtures)
3. **Spec parity:** Generated OpenAPI specs validate and structurally match Python output for identical inputs (strict golden fixtures)
4. **CDP capture completeness:** CDP mode captures all API-candidate requests needed to produce a useful OpenAPI spec, with known gaps (large binaries, service worker responses) documented
5. **Capture mode honesty:** CLI help and docs accurately describe the detection trade-offs of each mode (cdp-launch, cdp-attach, proxy) — no overclaiming stealth
6. **Binary size:** Target <20MB single binary
7. **Startup time:** <50ms (vs Python's ~500ms-1s import overhead)
8. **No runtime dependencies:** Single binary, no Python/Node/virtualenv required

# Phase 0 Results

Date: 2026-05-18

## Verdict

Phase 0 passes with documented caveats.

- Spike 0.1 Surf fingerprinting: pass.
- Spike 0.2 CDP capture: pass.
- Spike 0.3 golden fixture harness: pass.

The remaining caveats are implementation notes for Phase 1, not blockers:

- JA3 is unstable for Chrome-style fingerprints because extension order is randomized. JA4 matched real Chrome in the same environment.
- `cdp-launch` exposes `navigator.webdriver = true`; `cdp-attach` returned `false`.
- SSE produced `Network.eventSourceMessageReceived` and a response flow, but the streaming response body is not retrieved. Treat streaming body capture as best-effort.

## Spike 0.1: Surf

Command:

```sh
go run ./spikes/surf \
  --targets https://www.cloudflare.com,https://www.akamai.com,https://datadome.co \
  --baseline /tmp/apisniff-baseline.json \
  --output /tmp/apisniff-surf-report-with-baseline.json
```

Evidence:

- Surf TLS echo succeeded with HTTP/2.
- Surf JA4: `t13d1516h2_8daaf6152771_d8a2da3f94cd`
- Real Chrome JA4 from CDP against `https://tls.peet.ws/api/all`: `t13d1516h2_8daaf6152771_d8a2da3f94cd`
- Surf confirmed the expected Chrome post-quantum TLS key share group.
- Real Chrome confirmed the same post-quantum TLS key share group.
- curl-cffi and Impit baselines matched Surf at verdict-family level for Cloudflare, Akamai, and DataDome.

Target verdict-family comparison:

| Target | Surf | curl-cffi | Impit |
| --- | --- | --- | --- |
| `https://www.cloudflare.com` | blocked/challenged | blocked/challenged | blocked/challenged |
| `https://www.akamai.com` | blocked/challenged | blocked/challenged | blocked/challenged |
| `https://datadome.co` | blocked/challenged | blocked/challenged | blocked/challenged |

## Spike 0.2: CDP

Commands:

```sh
go run ./spikes/cdp \
  --mode launch \
  --remote-debugging-port 9222 \
  --user-data-dir /tmp/apisniff-cdp-localhost-sw-profile \
  --url http://127.0.0.1:8765/ \
  --out /tmp/apisniff-cdp-localhost-sw-flows.jsonl \
  --findings /tmp/apisniff-cdp-localhost-sw-findings.json \
  --timeout 90s \
  --wait 12s

go run ./spikes/cdp \
  --mode launch \
  --remote-debugging-port 0 \
  --user-data-dir /tmp/apisniff-cdp-port0-profile2 \
  --url http://127.0.0.1:8765/ \
  --out /tmp/apisniff-cdp-port0-2-flows.jsonl \
  --findings /tmp/apisniff-cdp-port0-2-findings.json \
  --timeout 90s \
  --wait 12s

go run ./spikes/cdp \
  --mode attach \
  --remote-url http://127.0.0.1:9225 \
  --url http://127.0.0.1:8765/ \
  --out /tmp/apisniff-cdp-attach2-flows.jsonl \
  --findings /tmp/apisniff-cdp-attach2-findings.json \
  --timeout 90s \
  --wait 12s
```

CDP matrix results:

| Mode | Requests | Responses | Bodies | WebSocket sent/received | SSE messages | Cache | Service worker | `navigator.webdriver` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| fixed-port launch | 10 | 10 | 9 | 1 / 1 | 1 | 1 | 1 | `true` |
| port-0 launch | 10 | 10 | 9 | 1 / 1 | 1 | 1 | 1 | `true` |
| attach | 10 | 10 | 9 | 1 / 1 | 1 | 1 | 1 | `false` |

The local CDP matrix exercised:

- HTML document
- small JSON
- 1 MB JSON
- 10 MB JSON
- binary response
- cached response
- service-worker response
- WebSocket send/receive
- EventSource/SSE

Python mitmproxy recon comparison:

- Bundle: `/Users/aaron/apisniff-captures/localtest-me_2026-05-18_23-36`
- Python recon captured 34 total flows and kept 6 API-candidate flows.
- Kept paths: `/`, `/json-small`, `/json-1mb`, `/json-10mb`, `/binary`, `/cached`.
- CDP captured those same API-candidate paths, plus additional browser-visible traffic (`/favicon.ico`, `/sw-controlled`, `/sse`, WebSocket/SSE events).

## Spike 0.3: Fixtures

Command:

```sh
go run ./spikes/fixtures
```

Result:

```text
ok: 3 classification results match testdata/golden/phase0/classify/expected.json
```

The fixture harness loads JSONL flows, loads expected classification JSON, runs the stub classifier, normalizes output, and reports a diff on mismatch.

## Verification

```sh
gofmt -w spikes
go mod tidy
go test ./...
go run ./spikes/fixtures
```

All commands passed.

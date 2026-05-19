# CDP Capture Spike

Phase 0.2 asks whether Chrome DevTools Protocol capture can produce usable `CapturedFlow` JSONL without putting a MITM proxy in the network path.

This spike:

- launches Chrome or attaches to a user-launched Chrome
- enables CDP `Network` events
- records request/response metadata
- fetches request post data and response bodies when CDP allows it
- emits Python-compatible `CapturedFlow` JSONL
- writes a findings report with Chrome version, `navigator.webdriver`, body retrieval failures, cache/service-worker tags, WebSocket counts, and SSE counts

## Run

Required verification command when Go and Chrome are available:

```sh
go run ./spikes/cdp \
  --url https://example.com \
  --out /tmp/apisniff-cdp-flows.jsonl \
  --findings /tmp/apisniff-cdp-findings.md
```

Launch mode defaults to a dedicated profile directory:

```sh
go run ./spikes/cdp \
  --mode launch \
  --remote-debugging-port 9222 \
  --user-data-dir ~/.apisniff/chrome-profile-phase0 \
  --url https://example.com
```

Attach mode expects Chrome to already be running with a DevTools port:

```sh
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9223 \
  --user-data-dir=/tmp/apisniff-cdp-user \
  --new-window https://example.com

go run ./spikes/cdp \
  --mode attach \
  --remote-url http://127.0.0.1:9223 \
  --url https://example.com
```

## Phase 0 Test Matrix

Run the same target through these configurations and compare `navigator.webdriver`, flow usefulness, and body failures:

| Case | Flags | Expected question |
| --- | --- | --- |
| Port 0 | `--mode launch --remote-debugging-port 0` | Does Chrome expose `navigator.webdriver` or fail remote debugging setup? |
| Fixed port | `--mode launch --remote-debugging-port 9222 --user-data-dir ~/.apisniff/chrome-profile-phase0` | Does the default recon mode capture useful flows with stable launch behavior? |
| Attach | `--mode attach --remote-url http://127.0.0.1:9223` | Does user-controlled Chrome reduce automation signals? |

For body coverage, run pages that exercise:

- small JSON responses
- 1 MB, 10 MB, and 100 MB responses
- binary assets
- cached responses
- service-worker-intercepted responses
- WebSocket frames
- EventSource/SSE messages

## Output Shape

`--out` is newline-delimited JSON matching Python `CapturedFlow.to_dict()`:

- `method`, `host`, `path`, `url`
- `request_headers`, `response_headers`
- `request_body` and `response_body` as base64 strings or `null`
- `_body_encoding: "base64"`
- `response_status`, `tags`, `timestamp`

`--findings` writes JSON unless the path ends in `.md`.

## Decision Gate Notes

This spike does not decide pass/fail by request count parity with mitmproxy. CDP can legitimately see a different stream. The Phase 0 decision should compare API-candidate coverage and whether the resulting flows can generate an equally useful OpenAPI surface.

Known body retrieval failures are expected for some cached, large, streaming, service-worker, or opaque responses. Those should be documented with target URLs and workarounds before Phase 1 starts.

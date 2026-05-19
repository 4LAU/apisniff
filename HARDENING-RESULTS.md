# Go Port Hardening Results

Status: complete.

## CDP Large Response Bodies

- Added integration coverage for a 2 MiB JSON API response captured through `cdp-launch`.
- CDP-captured flows now retain body-size metadata tags:
  - `response_encoded_bytes:<n>`
  - `response_body_bytes:<n>`
- Verified the large JSON response body is present in `flows.jsonl`.

## CDP WebSocket Capture

- Added CDP WebSocket event handling:
  - `Network.webSocketCreated`
  - `Network.webSocketWillSendHandshakeRequest`
  - `Network.webSocketHandshakeResponseReceived`
  - `Network.webSocketFrameSent`
  - `Network.webSocketFrameReceived`
  - `Network.webSocketFrameError`
  - `Network.webSocketClosed`
- Captured WebSocket flows retain frame count tags:
  - `websocket_sent_frames:<n>`
  - `websocket_received_frames:<n>`
  - `websocket_frame_errors:<n>` when applicable
- A bounded JSON frame summary is stored as the flow response body when no HTTP response body exists.
- Added a headless Chrome integration test that sends and receives WebSocket frames.

## Proxy HTTP/2

- Enabled `goproxy` HTTP/2 handling in proxy mode.
- Configured the proxy upstream transport to attempt HTTP/2.
- Captured proxy flows retain protocol tags:
  - `request_proto:<proto>`
  - `upstream_response_proto:<proto>`
- Added a proxy MITM integration test proving the backend receives HTTP/2 when the upstream supports it.

## Classifier Tag Preservation

- Fixed classifier behavior so capture-layer tags survive classification.
- Added a classifier regression test for preserving capture metadata tags.

## Validation

- Focused hardening tests:
  - `go test ./internal/classify ./internal/capture -v`
- Full verification:
  - `go test ./...`
  - `go vet ./...`
  - `go test -race ./internal/capture ./internal/replay ./internal/report ./internal/classify`
  - `uv run pytest tests -q`
  - `gitleaks detect --source . --log-opts='-1' --verbose`
  - stripped Go release build

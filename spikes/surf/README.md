# Surf Fingerprint Spike

Phase 0.1 asks whether Surf's Chrome impersonation can produce the browser TLS fingerprint signals apisniff needs.

This spike:

- builds a Surf client with `surf.NewClient().Builder().Impersonate().Chrome().Build().Unwrap()`
- requests a TLS echo endpoint, defaulting to `https://tls.peet.ws/api/all`
- extracts `tls.ja3_hash`, `tls.ja4`, `tls.ja3`, HTTP version, user agent, supported groups, and key shares from the echo JSON
- reports whether an X25519MLKEM768 / ML-KEM / Kyber hybrid key-share marker is present, absent, or inconclusive
- probes Cloudflare, Akamai, and DataDome marketing targets by default and records status, protocol, elapsed time, selected bot/CDN headers, and coarse block/challenge signals

## Run

Required verification command when Go is available:

```sh
go run ./spikes/surf --targets https://www.cloudflare.com,https://www.akamai.com,https://datadome.co
```

Useful variants:

```sh
go run ./spikes/surf \
  --echo https://tls.peet.ws/api/all \
  --targets https://www.cloudflare.com,https://www.akamai.com,https://datadome.co \
  --timeout 20s \
  --output spikes/surf/report.json
```

To compare Surf pass/block results with separately collected curl-cffi and Impit runs, pass a baseline JSON file:

```sh
go run ./spikes/surf \
  --baseline spikes/surf/baseline.json \
  --targets https://www.cloudflare.com,https://www.akamai.com,https://datadome.co
```

Accepted baseline shape:

```json
{
  "curl-cffi": [
    {"url": "https://www.cloudflare.com", "status": 200, "blocked": false}
  ],
  "impit": [
    {"url": "https://www.cloudflare.com", "status": 200, "blocked": false}
  ]
}
```

If you have authoritative Chrome 145 values from a real Chrome capture in the same environment, pass them explicitly:

```sh
go run ./spikes/surf \
  --known-ja3-hash '<chrome-145-ja3-hash>' \
  --known-ja4 '<chrome-145-ja4>'
```

The report is JSON. With no `--output`, it is written to stdout.

## Interpreting Results

The key fields are:

- `echo.tls.ja3_hash`, `echo.tls.ja4`, and `echo.tls.ja3`
- `echo.pq_key_share.status`
- `expected_comparison.ja3_hash.status` and `expected_comparison.ja4.status`
- each `targets[].blocked` and `targets[].challenge_signal`

`echo.pq_key_share.status` values:

- `present`: the echo JSON contained an X25519MLKEM768, ML-KEM, Kyber, decimal `4588`, or `0x11ec` marker in key-share/group data
- `absent`: the echo JSON exposed key-share/group data but none of the markers were found
- `inconclusive`: the echo service did not expose key-share details or the echo request failed

## What This Can Prove

This can prove that Surf's Chrome profile produces the JA3/JA4 values observed by the echo service, and whether the echo service exposes evidence of the post-quantum key share.

It can also give a first-pass Surf-only pass/block signal against real targets. The target probe is intentionally coarse: HTTP `403`, `429`, `503`, selected CDN/bot headers, and common challenge strings are treated as challenge/block indicators.

## What This Cannot Prove Alone

This spike does not run curl-cffi or Impit. The JSON includes a `baseline_comparison` note set to `not_run` until those tools are run separately against the same targets, from the same network, at roughly the same time. If a `--baseline` file is provided, the spike compares Surf's `blocked` value against each baseline row by URL.

The pass criteria from `PLAN-GO-PORT.md` require comparing Surf against curl-cffi and Impit. Use this spike's `targets[]` output as the Surf side of that comparison, then record the same URL/status/protocol/challenge fields for curl-cffi and Impit before making the final pass/fail call.

JA3 is also unstable for modern Chrome-style fingerprints because extension order can be randomized. Prefer JA4 and raw ClientHello/key-share evidence when deciding whether Surf is authentic enough for the Go port.

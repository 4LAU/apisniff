# Testing Policy

**This is law.** Every test in this repo must comply. Tests that violate this policy are deleted, not fixed.

---

## The Invariant Rule

Every test must protect a **stated invariant** — a behavior that would break silently without the test. The invariant does not need to be written as a comment in the code, but under audit, every test must be defensible: you must be able to answer "without this test, a change could ship that _____ and nobody would know until production." If you can't complete the sentence, the test has no reason to exist.

---

## Three-Gate Decision (before writing any test)

Ask these three questions in order. If any gate passes, **do not write the test:**

1. **Would this failure produce a visible signal in production?** (crash, traceback, empty output, HTTP error) → The app is the test. Don't write it.
2. **Does the language or framework already enforce this?** (type hints, dataclass validation, enum constraints) → Already covered. Don't write it.
3. **Is there already a test covering this seam?** → Search first. Don't duplicate.

If all three gates fail — the failure would be **silent** — write the test.

---

## Test Tiers

| Tier | Category | Rule |
|---|---|---|
| **1** | Security, data corruption, silent wrong output | Every distinct failure mode. One test per mode. Non-negotiable. |
| **2** | Core logic, wire contracts, classification accuracy | Happy path + the one error path that causes a silent incident. |
| **3** | Formatting, rendering, output cosmetics | **MANDATORY DELETE — no exceptions.** Do not test Rich panel layout, string formatting, or terminal aesthetics. |

---

## Mock Discipline

- **Mock only at the I/O boundary:** HTTP clients (`httpx`, `curl_cffi`), mitmproxy internals, filesystem (when testing non-IO logic), network sockets.
- **Never mock internal code.** If you're mocking `Classifier` to test `probe`, you're testing wiring — delete or restructure.
- **Never mock the classification pipeline.** Feed it real-shaped data and assert real-shaped output.
- **If a test mocks more than one layer, it's wrong.** Delete or restructure.

---

## Integration Over Unit

- **Unit tests:** Pure functions with no I/O only. `_normalize_path`, `_infer_schema`, `classify_results`, `_signal_matches`.
- **Integration tests:** Anything touching files, network, or multi-component pipelines.
- **When in doubt:** Integration test wins.
- **Do not unit-test orchestration.** `run_recon`, `run_spec`, CLI entry points — these are tested by smoke tests and integration tests, not unit tests.

---

## Property-Based Testing (hypothesis)

Any function where **silent numeric or logic corruption** is possible gets property-based tests:

- **Vendor signature matching:** random headers/cookies/body → never crashes, confidence is always valid enum value.
- **Path normalization:** random URL paths → output is valid, idempotent (`normalize(normalize(x)) == normalize(x)`).
- **Schema inference:** random JSON structures → output is valid OpenAPI schema, never crashes.
- **Classification pipeline:** random CapturedFlow inputs → never crashes, output is either None or a valid CapturedFlow.

Use `hypothesis` with `@given` strategies. Keep max examples reasonable (100, not 10000).

---

## Golden Fixtures

Wire contracts (HAR parsing, mitmproxy adapter, vendor signature matching against real sites) use **real captured data**, not synthetic JSON:

- Store in `tests/fixtures/`.
- Note capture date and source in a comment at the top of the fixture file or in a companion `.md`.
- One golden-fixture test per wire contract.
- Synthetic data is acceptable for unit tests of pure logic, never for integration tests of parsing/adaptation.

---

## Forbidden Patterns

| Pattern | Why | Consequence |
|---|---|---|
| `assert x is not None` as the primary assertion | Passes for almost any value | Delete |
| `assert isinstance(x, dict)` as the primary assertion | Tests shape, not content | Delete |
| `assert len(results) > 0` | Passes for wrong results | Assert specific values |
| Happy-path-only tests where failure is a visible crash | App is the test | Delete |
| Snapshot tests / golden-output string matching on rendered panels | Brittle, breaks on any Rich update | Delete |
| `@pytest.mark.flaky` or retry decorators | Flaky test = delete, not retry | Delete the test |
| Parametrize explosions (>5 cases for same invariant) | One test locks the contract; permutations are noise | Collapse to 1-3 cases |
| Tests that can't state their invariant under audit | Unjustified | Delete unchallenged |
| Mocking more than one layer | Testing wiring, not behavior | Delete or restructure |

---

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures only — no test logic
├── fixtures/                # Real captured data (HAR, response headers, etc.)
├── test_models.py           # Tier 2: data model invariants
├── test_vendors.py          # Tier 1: vendor matching correctness (silent wrong output)
├── test_classify.py         # Tier 1: classification pipeline (silent drops/keeps)
├── test_probe.py            # Tier 2: differential classification logic
├── test_spec.py             # Tier 1: schema inference, path normalization (silent corruption)
├── test_adapters.py         # Tier 2: wire contracts (HAR/mitmproxy → CapturedFlow)
├── test_output.py           # Tier 2: JSON serialization only (NOT Rich rendering)
├── test_cli.py              # Smoke: CLI entry points respond, --help works
├── test_recon.py            # Tier 2: JSONL read/write round-trip
└── test_properties.py       # Property-based tests (hypothesis)
```

---

## Enforcement

- **CI:** `pytest --strict-markers -v`. No warnings allowed.
- **Test audits:** Every test must be able to state its invariant on challenge. "Without this test, a change could ship that _____ and nobody would know." Tests that can't answer are deleted.
- **Quarterly review:** Grep for weak assertions (`is not None`, `isinstance`, `len(x) > 0` as primary assertion) — delete or strengthen.

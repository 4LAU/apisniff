"""Invariants that hold for every generated OpenAPI spec.

Each test function asserts one invariant, parameterized across every fixture
in the corpus that contains API-like flows.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from openapi_spec_validator import validate

from apisniff.bundle import load_flows
from apisniff.spec import generate_openapi

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------------------
# Fixture corpus — every file that can produce a non-empty spec.
# ---------------------------------------------------------------------------

FIXTURE_CASES = [
    ("minimal.har", "example.com"),
    ("minimal.burp.xml", "example.com"),
    ("minimal.jsonl", "example.com"),
    ("multisite.har", "example.com"),
    ("auth_variants.har", "example.com"),
]


def _ids(cases: list[tuple[str, str]]) -> list[str]:
    return [name for name, _ in cases]


def _load_spec(
    fixture_name: str,
    domain: str,
    *,
    include_examples: bool = False,
) -> dict:
    """Load flows from a fixture and generate an OpenAPI spec."""
    flows, _fmt = load_flows(str(FIXTURES_DIR / fixture_name))
    assert flows, f"fixture {fixture_name} produced no flows"
    return generate_openapi(flows, domain, include_examples=include_examples)


# ---------------------------------------------------------------------------
# Invariant 1: openapi_spec_validator.validate() passes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_spec_passes_structural_validation(fixture_name: str, domain: str):
    """Every generated spec must satisfy the OpenAPI 3.0 JSON Schema."""
    spec = _load_spec(fixture_name, domain)
    validate(spec)  # raises on failure


# ---------------------------------------------------------------------------
# Invariant 2: every {param} in a path has a matching in:path parameter
# ---------------------------------------------------------------------------

_PATH_PARAM_RE = re.compile(r"\{(\w+)\}")


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_path_params_declared(fixture_name: str, domain: str):
    """Every {param} placeholder in a path key must have a corresponding
    ``in: path`` parameter declaration in every operation on that path."""
    spec = _load_spec(fixture_name, domain)

    for path, methods in spec["paths"].items():
        expected_params = set(_PATH_PARAM_RE.findall(path))
        if not expected_params:
            continue
        for method, operation in methods.items():
            declared = {
                p["name"]
                for p in operation.get("parameters", [])
                if p["in"] == "path"
            }
            missing = expected_params - declared
            assert not missing, (
                f"{path}.{method} missing path parameter declarations: {missing}"
            )


# ---------------------------------------------------------------------------
# Invariant 3: response status codes are strings, not ints
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_response_status_codes_are_strings(fixture_name: str, domain: str):
    """OpenAPI 3.0 requires response status codes to be strings."""
    spec = _load_spec(fixture_name, domain)

    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            for status_key in operation.get("responses", {}):
                assert isinstance(status_key, str), (
                    f"{path}.{method}.responses[{status_key!r}] "
                    f"is {type(status_key).__name__}, expected str"
                )


# ---------------------------------------------------------------------------
# Invariant 4: same input produces identical output (determinism)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_deterministic_output(fixture_name: str, domain: str):
    """Running generate_openapi twice on the same flows must produce
    byte-identical output — non-determinism breaks diffing, caching, and CI."""
    flows, _ = load_flows(str(FIXTURES_DIR / fixture_name))
    spec_a = generate_openapi(flows, domain)
    spec_b = generate_openapi(flows, domain)
    assert spec_a == spec_b


# ---------------------------------------------------------------------------
# Invariant 5: paths keys are sorted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_paths_are_sorted(fixture_name: str, domain: str):
    """Path keys must be lexicographically sorted for deterministic human review."""
    spec = _load_spec(fixture_name, domain)
    path_keys = list(spec["paths"].keys())
    assert path_keys == sorted(path_keys), (
        f"Paths not sorted: {path_keys}"
    )


# ---------------------------------------------------------------------------
# Invariant 6: no example fields when include_examples=False
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_no_examples_by_default(fixture_name: str, domain: str):
    """Default behavior (include_examples=False) must not emit ``example``
    fields — they can leak captured data."""
    spec = _load_spec(fixture_name, domain, include_examples=False)
    serialized = json.dumps(spec)
    # "example" as a JSON key: look for the key pattern in serialized output.
    # Avoid false positives from strings like "x-apisniff-example" by checking
    # the exact JSON key pattern.
    assert '"example":' not in serialized, (
        "Found 'example' key in spec generated with include_examples=False"
    )


# ---------------------------------------------------------------------------
# Invariant 7: no Python-specific types in serialized output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_no_python_types_in_yaml(fixture_name: str, domain: str):
    """YAML output must not contain Python-specific literals (True, False,
    None). Consumers expect YAML booleans (true/false) and null."""
    spec = _load_spec(fixture_name, domain)
    yaml_out = yaml.dump(spec, sort_keys=False, default_flow_style=False)

    # In properly serialized YAML:
    #   Python True  -> "true"
    #   Python False -> "false"
    #   Python None  -> "null" or empty
    # If Python objects leak without conversion, they'd appear as "True",
    # "False", "None" (capital first letter, not valid YAML booleans).
    #
    # Match only standalone values — not substrings inside quoted strings or
    # words like "TrueColor". A YAML value `True` would appear as `: True\n`
    # or at the start of a bare list item `- True\n`.
    for python_literal in ("True", "False", "None"):
        # `: True\n` or `- True\n` — standalone YAML value positions
        pattern = rf"(?::\s+|^-\s+){python_literal}\s*$"
        matches = re.findall(pattern, yaml_out, re.MULTILINE)
        assert not matches, (
            f"Python literal '{python_literal}' found as YAML value "
            f"({len(matches)} occurrences)"
        )

    # Also verify JSON round-trip is clean (json.dumps converts properly)
    json.dumps(spec)  # raises TypeError if non-serializable types exist

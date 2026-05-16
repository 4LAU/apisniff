"""Invariants that hold for every generated OpenAPI spec.

Each test asserts one invariant parameterized across fixtures. Without these
tests, a spec change could silently produce structurally invalid output,
non-deterministic diffs, undeclared parameters, or leaked captured data.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from openapi_spec_validator import validate

from apisniff.bundle import load_flows
from apisniff.spec import generate_openapi

FIXTURES_DIR = Path(__file__).parent / "fixtures"

FIXTURE_CASES = [
    ("minimal.har", "example.com"),
    ("minimal.burp.xml", "example.com"),
    ("minimal.jsonl", "example.com"),
    ("multisite.har", "example.com"),
    ("auth_variants.har", "example.com"),
]


def _ids(cases):
    return [name for name, _ in cases]


def _load_spec(fixture_name, domain, *, include_examples=False):
    flows, _ = load_flows(str(FIXTURES_DIR / fixture_name))
    assert flows, f"fixture {fixture_name} produced no flows"
    return generate_openapi(flows, domain, include_examples=include_examples)


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_spec_passes_structural_validation(fixture_name, domain):
    spec = _load_spec(fixture_name, domain)
    validate(spec)


_PATH_PARAM_RE = re.compile(r"\{(\w+)\}")


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_path_params_declared(fixture_name, domain):
    """Every {param} must have a matching in:path parameter declaration."""
    spec = _load_spec(fixture_name, domain)
    for path, methods in spec["paths"].items():
        expected_params = set(_PATH_PARAM_RE.findall(path))
        if not expected_params:
            continue
        for method, operation in methods.items():
            declared = {
                p["name"] for p in operation.get("parameters", []) if p["in"] == "path"
            }
            missing = expected_params - declared
            assert not missing, f"{path}.{method} missing path params: {missing}"


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_deterministic_output(fixture_name, domain):
    """Same input must produce identical output."""
    flows, _ = load_flows(str(FIXTURES_DIR / fixture_name))
    assert generate_openapi(flows, domain) == generate_openapi(flows, domain)


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_paths_are_sorted(fixture_name, domain):
    spec = _load_spec(fixture_name, domain)
    path_keys = list(spec["paths"].keys())
    assert path_keys == sorted(path_keys), f"Paths not sorted: {path_keys}"


@pytest.mark.parametrize("fixture_name,domain", FIXTURE_CASES, ids=_ids(FIXTURE_CASES))
def test_no_examples_by_default(fixture_name, domain):
    """include_examples=False must not emit example keys (data leak risk)."""
    spec = _load_spec(fixture_name, domain, include_examples=False)
    assert '"example":' not in json.dumps(spec)

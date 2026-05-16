"""Secret and credential invariants for generated specs and shared bundles.

Uses the ``redaction.jsonl`` fixture which intentionally contains secrets:
bearer tokens, sk_live_ keys, password fields, api_key query params,
JWT-shaped values, and AWS-style secret keys.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from apisniff.bundle import load_flows
from apisniff.models import SessionStats
from apisniff.share import share_bundle
from apisniff.spec import generate_openapi

FIXTURES_DIR = Path(__file__).parent / "fixtures"

REDACTION_FIXTURE = str(FIXTURES_DIR / "redaction.jsonl")

# Patterns that must never appear in any output derived from the fixture.
SECRET_PATTERNS = [
    "Bearer ",
    "sk_live_",
    "eyJ",          # JWT prefix (base64 of '{"')
    "Basic ",
    "SuperSecret",  # password value from register flow
    "wJalrXUtn",    # AWS secret key prefix
    "pk_test_",     # Stripe publishable key in query param
    "rt_live_",     # refresh token value
]


def _load_redaction_flows():
    flows, fmt = load_flows(REDACTION_FIXTURE)
    assert flows, "redaction fixture produced no flows"
    assert fmt == "jsonl"
    return flows


# ---------------------------------------------------------------------------
# Invariant 1: spec with include_examples=True contains no raw secrets
# ---------------------------------------------------------------------------


def test_spec_with_examples_contains_no_secrets():
    """When examples are enabled, secret values from captured traffic must
    be redacted — they should never appear in the serialized YAML output."""
    flows = _load_redaction_flows()
    spec = generate_openapi(flows, "example.com", include_examples=True)
    yaml_out = yaml.dump(spec, sort_keys=False, default_flow_style=False)

    for pattern in SECRET_PATTERNS:
        assert pattern not in yaml_out, (
            f"Secret pattern {pattern!r} leaked into YAML spec with examples enabled"
        )


# ---------------------------------------------------------------------------
# Invariant 2: spec without examples contains no example keys
# ---------------------------------------------------------------------------


def test_spec_without_examples_has_no_example_keys():
    """Defense in depth: when examples are disabled (the default), no
    ``example`` keys should appear anywhere in the spec."""
    flows = _load_redaction_flows()
    spec = generate_openapi(flows, "example.com", include_examples=False)
    serialized = json.dumps(spec)
    assert '"example":' not in serialized, (
        "Found 'example' key in spec generated without examples"
    )


# ---------------------------------------------------------------------------
# Invariant 3: shared bundle contains no raw secrets
# ---------------------------------------------------------------------------


def test_shared_bundle_contains_no_secrets(tmp_path):
    """The share_bundle() output directory must not contain any raw secret
    values from the original captured traffic."""
    flows = _load_redaction_flows()

    # Build a realistic source bundle directory
    src_dir = tmp_path / "src_bundle"
    src_dir.mkdir()
    with open(src_dir / "flows.jsonl", "w") as f:
        for flow in flows:
            f.write(flow.to_jsonl() + "\n")
    stats = SessionStats(
        domain="example.com",
        started_at="2025-01-15T12:00:00Z",
        duration_seconds=60.0,
        total_flows=len(flows),
        kept_flows=len(flows),
        dropped={},
    )
    (src_dir / "session.json").write_text(json.dumps(stats.to_dict()))

    dst_dir = tmp_path / "shared"
    result = share_bundle(str(src_dir), str(dst_dir), "example.com")
    assert result["flows_processed"] > 0

    # Scan every file in the output directory for secret patterns
    for output_file in dst_dir.iterdir():
        if not output_file.is_file():
            continue
        content = output_file.read_text(errors="replace")
        for pattern in SECRET_PATTERNS:
            assert pattern not in content, (
                f"Secret pattern {pattern!r} leaked into shared bundle "
                f"file {output_file.name}"
            )


# ---------------------------------------------------------------------------
# Invariant 4: sensitive field names always redacted in examples
# ---------------------------------------------------------------------------


def test_sensitive_fields_always_redacted():
    """Fields named password, secret, token, api_key (and similar) must
    have their example values replaced with a redaction marker, regardless
    of the actual value content."""
    flows = _load_redaction_flows()
    spec = generate_openapi(flows, "example.com", include_examples=True)

    redacted = "***REDACTED***"

    def _check_schema(schema: dict, breadcrumb: str = "") -> None:
        """Recursively walk a schema and verify sensitive field examples."""
        if "$ref" in schema:
            ref_name = schema["$ref"].rpartition("/")[2]
            resolved = spec.get("components", {}).get("schemas", {}).get(ref_name, {})
            _check_schema(resolved, breadcrumb=f"{breadcrumb}->$ref({ref_name})")
            return

        props = schema.get("properties", {})
        for field_name, field_schema in props.items():
            path = f"{breadcrumb}.{field_name}" if breadcrumb else field_name

            # Check nested objects recursively
            if field_schema.get("type") == "object" and "properties" in field_schema:
                _check_schema(field_schema, breadcrumb=path)
                continue

            # Sensitive field name patterns (must match spec.py's redaction logic)
            sensitive_names = {"password", "secret", "token", "api_key", "auth",
                              "credential", "refresh_token", "aws_secret"}
            if field_name in sensitive_names and "example" in field_schema:
                assert field_schema["example"] == redacted, (
                    f"Sensitive field {path!r} has example "
                    f"{field_schema['example']!r} instead of {redacted!r}"
                )

    for path_key, methods in spec["paths"].items():
        for method, operation in methods.items():
            # Check response schemas
            for status, response in operation.get("responses", {}).items():
                for _ct, media in response.get("content", {}).items():
                    schema = media.get("schema", {})
                    _check_schema(
                        schema,
                        breadcrumb=f"{path_key}.{method}.responses.{status}",
                    )
            # Check request body schemas
            req_body = operation.get("requestBody", {})
            for _ct, media in req_body.get("content", {}).items():
                schema = media.get("schema", {})
                _check_schema(
                    schema,
                    breadcrumb=f"{path_key}.{method}.requestBody",
                )

# tests/test_spec.py
import yaml

from apisniff.auth import AuthPattern
from apisniff.models import CapturedFlow
from apisniff.spec import _infer_schema, _normalize_path, generate_openapi


def _flow(
    method="GET",
    path="/api/v1/users",
    status=200,
    body=b'[{"id": 1, "name": "Alice"}]',
):
    return CapturedFlow(
        method=method,
        host="example.com",
        path=path,
        url=f"https://example.com{path}",
        request_headers={},
        request_body=b"",
        response_status=status,
        response_headers={"content-type": "application/json"},
        response_body=body,
    )


def test_normalize_path_uuid():
    result = _normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000")
    assert result == "/api/users/{id}"


def test_normalize_path_numeric():
    assert _normalize_path("/api/users/12345") == "/api/users/{id}"


def test_normalize_path_no_params():
    assert _normalize_path("/api/users") == "/api/users"


def test_infer_schema_object():
    schema = _infer_schema({"id": 1, "name": "Alice", "active": True})
    assert schema["type"] == "object"
    assert "id" in schema["properties"]
    assert schema["properties"]["id"]["type"] == "integer"
    assert schema["properties"]["name"]["type"] == "string"
    assert schema["properties"]["active"]["type"] == "boolean"


def test_infer_schema_array():
    schema = _infer_schema([{"id": 1}, {"id": 2}])
    assert schema["type"] == "array"
    assert schema["items"]["type"] == "object"


def test_generate_openapi_basic():
    flows = [
        _flow("GET", "/api/v1/users"),
        _flow(
            "GET",
            "/api/v1/users/123",
            body=b'{"id": 123, "name": "Bob"}',
        ),
        _flow(
            "POST",
            "/api/v1/users",
            body=b'{"id": 124, "name": "New"}',
        ),
    ]
    spec = generate_openapi(flows, "example.com")
    assert spec["openapi"] == "3.0.3"
    assert "/api/v1/users" in spec["paths"]
    assert "/api/v1/users/{id}" in spec["paths"]
    assert "get" in spec["paths"]["/api/v1/users"]
    assert "post" in spec["paths"]["/api/v1/users"]


def test_generate_openapi_yaml_output():
    flows = [_flow()]
    spec = generate_openapi(flows, "example.com")
    yaml_str = yaml.dump(spec, sort_keys=False)
    assert "openapi:" in yaml_str


def test_x_observed_auth_default():
    """Default behavior: extensions only, no securitySchemes."""
    flows = [_flow()]
    patterns = [
        AuthPattern(auth_type="bearer", detail="authorization: bearer", flow_count=5),
        AuthPattern(auth_type="token_endpoint", detail="/oauth/token", flow_count=1),
    ]
    spec = generate_openapi(flows, "example.com", auth_patterns=patterns)
    assert "x-observed-auth" in spec
    assert any(a["type"] == "bearer" for a in spec["x-observed-auth"])
    assert "x-observed-token-endpoints" in spec
    assert "/oauth/token" in spec["x-observed-token-endpoints"]
    # securitySchemes NOT added by default
    assert "components" not in spec


def test_security_schemes_opt_in_bearer():
    """securitySchemes only when infer_schemes=True."""
    flows = [_flow()]
    patterns = [AuthPattern(auth_type="bearer", detail="authorization: bearer", flow_count=5)]
    spec = generate_openapi(flows, "example.com", auth_patterns=patterns, infer_schemes=True)
    schemes = spec["components"]["securitySchemes"]
    assert "bearer" in schemes
    assert schemes["bearer"]["type"] == "http"
    assert schemes["bearer"]["scheme"] == "bearer"
    # Extensions still present
    assert "x-observed-auth" in spec


def test_security_schemes_opt_in_api_key():
    flows = [_flow()]
    patterns = [AuthPattern(auth_type="api_key_header", detail="x-api-key", flow_count=3)]
    spec = generate_openapi(flows, "example.com", auth_patterns=patterns, infer_schemes=True)
    schemes = spec["components"]["securitySchemes"]
    assert "api_key_header" in schemes
    assert schemes["api_key_header"]["in"] == "header"
    assert schemes["api_key_header"]["name"] == "x-api-key"


def test_no_top_level_security_even_with_flag():
    flows = [_flow()]
    patterns = [AuthPattern(auth_type="bearer", detail="authorization: bearer", flow_count=5)]
    spec = generate_openapi(flows, "example.com", auth_patterns=patterns, infer_schemes=True)
    assert "security" not in spec


def test_no_auth_patterns_no_extensions():
    flows = [_flow()]
    spec = generate_openapi(flows, "example.com")
    assert "components" not in spec
    assert "x-observed-auth" not in spec

# tests/test_spec.py
import yaml

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

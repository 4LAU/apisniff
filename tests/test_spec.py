# tests/test_spec.py


from apisniff.auth import AuthPattern
from apisniff.models import CapturedFlow, normalize_path
from apisniff.spec import (
    _infer_schema,
    is_api_flow,
    generate_openapi,
)


def _flow(
    method="GET",
    path="/api/v1/users",
    status=200,
    body=b'[{"id": 1, "name": "Alice"}]',
    request_headers=None,
    request_body=b"",
    response_headers=None,
):
    if response_headers is None:
        response_headers = {"content-type": "application/json"}
    if request_headers is None:
        request_headers = {}
    return CapturedFlow(
        method=method,
        host="example.com",
        path=path,
        url=f"https://example.com{path}",
        request_headers=request_headers,
        request_body=request_body,
        response_status=status,
        response_headers=response_headers,
        response_body=body,
    )


def _resp_schema(spec, path="/api/v1/users", method="get", status="200"):
    return (
        spec["paths"][path][method]["responses"][status]
        ["content"]["application/json"]["schema"]
    )


def _req_schema(spec, path="/api/v1/users", method="post", ct="application/json"):
    return spec["paths"][path][method]["requestBody"]["content"][ct]["schema"]


def test_normalize_path_uuid():
    result = normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000")
    assert result == "/api/users/{id}"


def test_normalize_path_numeric():
    assert normalize_path("/api/users/12345") == "/api/users/{id}"


def test_normalize_path_no_params():
    assert normalize_path("/api/users") == "/api/users"


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


# ── Part A: is_api_flow tests ──────────────────────────────────────


def testis_api_flow_json_response():
    """JSON 200 is API traffic."""
    flow = _flow(status=200)
    assert is_api_flow(flow) is True


def testis_api_flow_json_error():
    """JSON 404 is still API traffic."""
    flow = _flow(status=404, body=b'{"error": "not found"}')
    assert is_api_flow(flow) is True


def testis_api_flow_form_post():
    """form-urlencoded POST (even with HTML response) is API traffic."""
    flow = _flow(
        method="POST",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_body=b"username=alice&password=secret",
        response_headers={"content-type": "text/html"},
        body=b"<html>OK</html>",
    )
    assert is_api_flow(flow) is True


def testis_api_flow_multipart():
    """multipart upload is API traffic."""
    mp_body = (
        b"--abc\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        b"\r\ndata\r\n--abc--"
    )
    flow = _flow(
        method="POST",
        request_headers={"content-type": "multipart/form-data; boundary=abc"},
        request_body=mp_body,
        response_headers={"content-type": "text/plain"},
        body=b"OK",
    )
    assert is_api_flow(flow) is True


def testis_api_flow_html_page_excluded():
    """Pure HTML GET is not API traffic."""
    flow = _flow(
        response_headers={"content-type": "text/html"},
        body=b"<html><body>Hello</body></html>",
    )
    assert is_api_flow(flow) is False


def testis_api_flow_case_insensitive_content_type():
    """Mixed case Content-Type matched."""
    flow = _flow(
        response_headers={"Content-Type": "Application/JSON; charset=utf-8"},
        body=b'{"ok": true}',
    )
    assert is_api_flow(flow) is True


# ── Part B: Aggregation model tests ─────────────────────────────────


def test_query_params_in_spec():
    """Query params from captured flows appear as OpenAPI parameters."""
    flow = _flow(path="/api/v1/users?page=1&limit=10")
    spec = generate_openapi([flow], "example.com")
    params = spec["paths"]["/api/v1/users"]["get"]["parameters"]
    param_names = {p["name"] for p in params}
    assert "page" in param_names
    assert "limit" in param_names
    assert all(p["in"] == "query" for p in params)


def test_query_params_merged_across_flows():
    """Multiple flows merge query params."""
    f1 = _flow(path="/api/v1/users?page=1")
    f2 = _flow(path="/api/v1/users?page=2&sort=name")
    spec = generate_openapi([f1, f2], "example.com")
    params = spec["paths"]["/api/v1/users"]["get"]["parameters"]
    param_names = {p["name"] for p in params}
    assert param_names == {"page", "sort"}


def test_no_query_params_no_parameters_key():
    """No params = no parameters key."""
    flow = _flow(path="/api/v1/users")
    spec = generate_openapi([flow], "example.com")
    assert "parameters" not in spec["paths"]["/api/v1/users"]["get"]


def test_multiple_response_codes_aggregated():
    """200 and 404 produce two response entries."""
    f200 = _flow(status=200, body=b'{"id": 1}')
    f404 = _flow(status=404, body=b'{"error": "not found"}')
    spec = generate_openapi([f200, f404], "example.com")
    responses = spec["paths"]["/api/v1/users"]["get"]["responses"]
    assert "200" in responses
    assert "404" in responses


def test_multiple_content_types_aggregated():
    """JSON and form POST produce both in requestBody."""
    f_json = _flow(
        method="POST",
        request_headers={"content-type": "application/json"},
        request_body=b'{"name": "Alice"}',
    )
    f_form = _flow(
        method="POST",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_body=b"name=Alice",
    )
    spec = generate_openapi([f_json, f_form], "example.com")
    content = spec["paths"]["/api/v1/users"]["post"]["requestBody"]["content"]
    assert "application/json" in content
    assert "application/x-www-form-urlencoded" in content


def test_response_schemas_merged_across_flows():
    """Two 200s with different fields merge."""
    f1 = _flow(body=b'{"id": 1}')
    f2 = _flow(body=b'{"id": 2, "email": "a@b.com"}')
    spec = generate_openapi([f1, f2], "example.com")
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert "id" in props
    assert "email" in props


def test_request_body_schemas_merged_across_flows():
    """Two JSON POSTs merge schemas."""
    f1 = _flow(
        method="POST",
        request_headers={"content-type": "application/json"},
        request_body=b'{"name": "Alice"}',
    )
    f2 = _flow(
        method="POST",
        request_headers={"content-type": "application/json"},
        request_body=b'{"name": "Bob", "age": 30}',
    )
    spec = generate_openapi([f1, f2], "example.com")
    schema = _req_schema(spec)
    props = schema["properties"]
    assert "name" in props
    assert "age" in props


def test_content_type_case_insensitive():
    """Mixed-case Content-Type matched for request body."""
    flow = _flow(
        method="POST",
        request_headers={"Content-Type": "Application/JSON"},
        request_body=b'{"key": "val"}',
    )
    spec = generate_openapi([flow], "example.com")
    content = spec["paths"]["/api/v1/users"]["post"]["requestBody"]["content"]
    assert "application/json" in content


def test_empty_first_response_upgraded_by_later_json():
    """Non-JSON response upgraded by later JSON response."""
    f_html = _flow(
        status=200,
        response_headers={"content-type": "text/html"},
        body=b"<html>OK</html>",
        # Still included as API flow because request_headers might match
        request_headers={"content-type": "application/json"},
        request_body=b"{}",
    )
    f_json = _flow(
        status=200,
        body=b'{"result": "ok"}',
    )
    spec = generate_openapi([f_html, f_json], "example.com")
    resp_200 = spec["paths"]["/api/v1/users"]["get"]["responses"]["200"]
    # The JSON flow should have contributed a schema
    assert "content" in resp_200
    schema = resp_200["content"]["application/json"]["schema"]
    assert schema["properties"]["result"]["type"] == "string"


def test_empty_array_enriched_by_populated_array():
    """[] enriched by [{...}]."""
    f_empty = _flow(body=b"[]")
    f_populated = _flow(body=b'[{"id": 1, "name": "Alice"}]')
    spec = generate_openapi([f_empty, f_populated], "example.com")
    schema = _resp_schema(spec)
    assert schema["type"] == "array"
    assert schema["items"].get("type") == "object"
    assert "id" in schema["items"]["properties"]


# ── Part C: Examples with secret redaction ───────────────────────────


def test_examples_in_response_schema():
    """include_examples=True adds example values."""
    flow = _flow(body=b'{"id": 1, "name": "Alice"}')
    spec = generate_openapi([flow], "example.com", include_examples=True)
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert props["id"]["example"] == 1
    assert props["name"]["example"] == "Alice"


def test_examples_redact_secrets():
    """Bearer tokens and API keys redacted."""
    flow = _flow(body=b'{"token": "bearer abc123", "key": "sk_live_secret"}')
    spec = generate_openapi([flow], "example.com", include_examples=True)
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert props["token"]["example"] == "***REDACTED***"
    assert props["key"]["example"] == "***REDACTED***"


def test_examples_redact_mid_string_secrets():
    """Secrets not at start of string are still redacted."""
    flow = _flow(body=b'{"auth": "token=sk_live_abc", "header": "Authorization: Bearer eyJhbGc"}')
    spec = generate_openapi([flow], "example.com", include_examples=True)
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert props["auth"]["example"] == "***REDACTED***"
    assert props["header"]["example"] == "***REDACTED***"


def test_examples_truncate_long_strings():
    """Strings >200 chars truncated."""
    long_str = "a" * 300
    flow = _flow(body=f'{{"text": "{long_str}"}}'.encode())
    spec = generate_openapi([flow], "example.com", include_examples=True)
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert len(props["text"]["example"]) == 203  # 200 + "..."
    assert props["text"]["example"].endswith("...")


def test_examples_off_by_default():
    """No example fields without include_examples."""
    flow = _flow(body=b'{"id": 1, "name": "Alice"}')
    spec = generate_openapi([flow], "example.com")
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert "example" not in props["id"]
    assert "example" not in props["name"]


# ── Part D: Form body parsing tests ─────────────────────────────────


def test_form_urlencoded_request_body():
    """Form body appears in spec."""
    flow = _flow(
        method="POST",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_body=b"username=alice&password=secret",
    )
    spec = generate_openapi([flow], "example.com")
    content = spec["paths"]["/api/v1/users"]["post"]["requestBody"]["content"]
    assert "application/x-www-form-urlencoded" in content
    schema = content["application/x-www-form-urlencoded"]["schema"]
    assert schema["type"] == "object"
    assert "username" in schema["properties"]
    assert "password" in schema["properties"]


def test_multipart_form_data_request_body():
    """Multipart fields appear, file fields have format: binary."""
    body = (
        b"--boundary123\r\n"
        b'Content-Disposition: form-data; name="description"\r\n\r\n'
        b"A file upload\r\n"
        b"--boundary123\r\n"
        b'Content-Disposition: form-data; name="file"; filename="photo.jpg"\r\n'
        b"Content-Type: image/jpeg\r\n\r\n"
        b"<binary data>\r\n"
        b"--boundary123--"
    )
    flow = _flow(
        method="POST",
        path="/api/v1/upload",
        request_headers={"content-type": "multipart/form-data; boundary=boundary123"},
        request_body=body,
    )
    spec = generate_openapi([flow], "example.com")
    content = spec["paths"]["/api/v1/upload"]["post"]["requestBody"]["content"]
    assert "multipart/form-data" in content
    schema = content["multipart/form-data"]["schema"]
    assert "description" in schema["properties"]
    assert schema["properties"]["file"]["format"] == "binary"

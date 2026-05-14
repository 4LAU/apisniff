# tests/test_spec.py


from apisniff.auth import AuthPattern
from apisniff.models import CapturedFlow
from apisniff.spec import (
    _infer_schema,
    generate_openapi,
    is_api_flow,
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


def test_no_top_level_security_even_with_flag():
    flows = [_flow()]
    patterns = [AuthPattern(auth_type="bearer", detail="authorization: bearer", flow_count=5)]
    spec = generate_openapi(flows, "example.com", auth_patterns=patterns, infer_schemes=True)
    assert "security" not in spec


# ── Part A: is_api_flow tests ──────────────────────────────────────


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


def testis_api_flow_html_page_excluded():
    """Pure HTML GET is not API traffic."""
    flow = _flow(
        response_headers={"content-type": "text/html"},
        body=b"<html><body>Hello</body></html>",
    )
    assert is_api_flow(flow) is False


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


def test_multiple_response_codes_aggregated():
    """200 and 404 produce two response entries."""
    f200 = _flow(status=200, body=b'{"id": 1}')
    f404 = _flow(status=404, body=b'{"error": "not found"}')
    spec = generate_openapi([f200, f404], "example.com")
    responses = spec["paths"]["/api/v1/users"]["get"]["responses"]
    assert "200" in responses
    assert "404" in responses


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


def test_examples_redact_secrets():
    """Bearer tokens and API keys redacted."""
    flow = _flow(body=b'{"token": "bearer abc123", "key": "sk_live_secret"}')
    spec = generate_openapi([flow], "example.com", include_examples=True)
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert props["token"]["example"] == "***REDACTED***"
    assert props["key"]["example"] == "***REDACTED***"


def test_examples_off_by_default():
    """No example fields without include_examples."""
    flow = _flow(body=b'{"id": 1, "name": "Alice"}')
    spec = generate_openapi([flow], "example.com")
    schema = _resp_schema(spec)
    props = schema["properties"]
    assert "example" not in props["id"]
    assert "example" not in props["name"]


def test_examples_redact_by_field_name_password():
    """Values under sensitive field names are redacted regardless of content."""
    flow = _flow(body=b'{"password": "hunter2", "username": "alice"}')
    spec = generate_openapi([flow], "example.com", include_examples=True)
    props = _resp_schema(spec)["properties"]
    assert props["password"]["example"] == "***REDACTED***"
    assert props["username"]["example"] == "alice"


def test_examples_redact_nested_sensitive_field():
    """Sensitive field names redacted inside nested objects."""
    flow = _flow(body=b'{"user": {"name": "alice", "credential": "s3cr3t"}}')
    spec = generate_openapi([flow], "example.com", include_examples=True)
    nested = _resp_schema(spec)["properties"]["user"]["properties"]
    assert nested["name"]["example"] == "alice"
    assert nested["credential"]["example"] == "***REDACTED***"


def test_examples_sensitive_field_boundaries():
    """Sensitive words redact as components, not substrings."""
    flow = _flow(body=b'{"auth": "x", "auth_code": "y", "author": "Jane"}')
    spec = generate_openapi([flow], "example.com", include_examples=True)
    props = _resp_schema(spec)["properties"]
    assert props["auth"]["example"] == "***REDACTED***"
    assert props["auth_code"]["example"] == "***REDACTED***"
    assert props["author"]["example"] == "Jane"


def test_examples_token_secret_boundaries():
    """'token'/'secret' redact as components, not inside 'secretariat'/'max_tokens'."""
    flow = _flow(
        body=b'{"secret": "s", "secret_key": "k", "secretariat": "UN",'
        b' "token": "t", "csrf_token": "ct", "max_tokens": 100}'
    )
    spec = generate_openapi([flow], "example.com", include_examples=True)
    props = _resp_schema(spec)["properties"]
    assert props["secret"]["example"] == "***REDACTED***"
    assert props["secret_key"]["example"] == "***REDACTED***"
    assert props["secretariat"]["example"] == "UN"
    assert props["token"]["example"] == "***REDACTED***"
    assert props["csrf_token"]["example"] == "***REDACTED***"
    assert props["max_tokens"]["example"] == 100


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


def test_multipart_sensitive_field_redacted():
    """Multipart field with sensitive name gets example redacted."""
    body = (
        b"--bound\r\n"
        b'Content-Disposition: form-data; name="password"\r\n\r\n'
        b"hunter2\r\n"
        b"--bound--"
    )
    flow = _flow(
        method="POST",
        path="/api/v1/login",
        request_headers={"content-type": "multipart/form-data; boundary=bound"},
        request_body=body,
    )
    spec = generate_openapi([flow], "example.com", include_examples=True)
    schema = spec["paths"]["/api/v1/login"]["post"]["requestBody"]["content"]
    props = schema["multipart/form-data"]["schema"]["properties"]
    assert props["password"]["example"] == "***REDACTED***"

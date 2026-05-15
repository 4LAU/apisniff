import json

import yaml
from openapi_spec_validator import validate

from apisniff.auth import AuthPattern
from apisniff.models import CapturedFlow
from apisniff.spec import (
    generate_openapi as _generate_openapi,
)
from apisniff.spec import (
    is_api_flow,
    run_spec,
)
from apisniff.spec_schema import _infer_schema, _merge_schemas


def generate_openapi(*args, **kwargs):
    spec = _generate_openapi(*args, **kwargs)
    validate(spec)
    return spec


def _flow(
    method="GET",
    path="/api/v1/users",
    host="example.com",
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
        host=host,
        path=path,
        url=f"https://{host}{path}",
        request_headers=request_headers,
        request_body=request_body,
        response_status=status,
        response_headers=response_headers,
        response_body=body,
    )


def _resp_schema(spec, path="/api/v1/users", method="get", status="200"):
    schema = (
        spec["paths"][path][method]["responses"][status]
        ["content"]["application/json"]["schema"]
    )
    return _resolve_schema(spec, schema)


def _req_schema(spec, path="/api/v1/users", method="post", ct="application/json"):
    schema = spec["paths"][path][method]["requestBody"]["content"][ct]["schema"]
    return _resolve_schema(spec, schema)


def _resolve_schema(spec, schema):
    ref = schema.get("$ref") if isinstance(schema, dict) else None
    if not ref:
        return schema
    _, _, name = ref.rpartition("/")
    return spec["components"]["schemas"][name]


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


def test_merge_schemas_conflicting_scalar_types_falls_back_to_string():
    merged = _merge_schemas({"type": "integer"}, {"type": "string"})

    assert merged == {
        "type": "string",
        "x-apisniff-observed-types": ["integer", "string"],
    }


def test_infer_schema_numeric_keyed_object_as_map():
    schema = _infer_schema({"123": {"name": "Alice"}, "456": {"name": "Bob"}})

    assert schema["type"] == "object"
    assert "properties" not in schema
    assert schema["additionalProperties"]["properties"]["name"]["type"] == "string"


def test_infer_schema_depth_guard_marks_truncated():
    value = current = {}
    for _ in range(25):
        current["child"] = {}
        current = current["child"]

    schema = _infer_schema(value, max_depth=3)

    child = schema["properties"]["child"]["properties"]["child"]["properties"]["child"]
    assert child["x-apisniff-truncated"] is True


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
    assert "/api/v1/users/{userId}" in spec["paths"]
    assert "get" in spec["paths"]["/api/v1/users"]
    assert "post" in spec["paths"]["/api/v1/users"]


def test_generate_openapi_strips_path_from_server_url():
    spec = generate_openapi([_flow()], "www.example.com/app")

    assert spec["info"]["title"] == "www.example.com API"
    assert spec["servers"] == [{"url": "https://www.example.com"}]


def test_run_spec_writes_surface_inventory_sidecar(tmp_path):
    business = _flow()
    antibot = _flow(
        method="POST",
        path="/jMdNhK4DL/bTQsJS7e/Q/XNYrQm1k/Mn1tPnsWAg/bxM/MaQZNbw4u",
        request_headers={"content-type": "text/plain;charset=UTF-8"},
        request_body=b'{"sensor_data":"3;0;1"}',
    )
    flows_file = tmp_path / "flows.jsonl"
    flows_file.write_text(business.to_jsonl() + "\n" + antibot.to_jsonl() + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec("example.com", input_file=str(flows_file), output_file=str(output_file))

    surface = json.loads((tmp_path / "openapi.surface.json").read_text())
    categories = {entry["category"] for entry in surface}
    assert categories == {"business_api", "antibot"}


def test_run_spec_observed_auth_uses_filtered_spec_flows(tmp_path):
    included = _flow(request_headers={"authorization": "Bearer real-token"})
    excluded = CapturedFlow(
        method="POST",
        host="rum-ingest.us0.signalfx.com",
        path="/v1/rum",
        url="https://rum-ingest.us0.signalfx.com/v1/rum",
        request_headers={"authorization": "Bearer telemetry-token"},
        request_body=b"",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b"{}",
    )
    flows_file = tmp_path / "flows.jsonl"
    flows_file.write_text(included.to_jsonl() + "\n" + excluded.to_jsonl() + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec("example.com", input_file=str(flows_file), output_file=str(output_file))

    spec = yaml.safe_load(output_file.read_text())
    assert spec["x-observed-auth"] == [
        {"type": "bearer", "detail": "authorization: bearer", "flow_count": 1}
    ]


def test_run_spec_include_third_party_adds_api_dependency(tmp_path):
    business = _flow(path="/api/users")
    dependency = _flow(host="api.vendor.test", path="/v1/profile")
    flows_file = tmp_path / "flows.jsonl"
    flows_file.write_text(business.to_jsonl() + "\n" + dependency.to_jsonl() + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec(
        "example.com",
        input_file=str(flows_file),
        output_file=str(output_file),
        include_third_party=True,
    )

    spec = yaml.safe_load(output_file.read_text())
    assert "/api/users" in spec["paths"]
    assert "/v1/profile" in spec["paths"]


def test_same_site_subdomain_inventory_not_default_openapi(tmp_path):
    requested = _flow(host="www.example.com", path="/api/users")
    same_site = _flow(host="api.example.com", path="/api/orders")
    flows_file = tmp_path / "flows.jsonl"
    flows_file.write_text(requested.to_jsonl() + "\n" + same_site.to_jsonl() + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec("www.example.com", input_file=str(flows_file), output_file=str(output_file))

    spec = yaml.safe_load(output_file.read_text())
    assert "/api/users" in spec["paths"]
    assert "/api/orders" not in spec["paths"]

    surface = json.loads((tmp_path / "openapi.surface.json").read_text())
    same_site_entry = next(entry for entry in surface if entry["host"] == "api.example.com")
    assert same_site_entry["category"] == "unknown_api_like"
    assert same_site_entry["host_role"] == "same_site"
    assert same_site_entry["included_in_openapi"] is False


def test_include_host_adds_same_site_subdomain(tmp_path):
    requested = _flow(host="www.example.com", path="/api/users")
    same_site = _flow(host="api.example.com", path="/api/orders")
    flows_file = tmp_path / "flows.jsonl"
    flows_file.write_text(requested.to_jsonl() + "\n" + same_site.to_jsonl() + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec(
        "www.example.com",
        input_file=str(flows_file),
        output_file=str(output_file),
        include_hosts=["api.example.com"],
    )

    spec = yaml.safe_load(output_file.read_text())
    assert "/api/orders" in spec["paths"]


def test_include_host_does_not_promote_captcha_without_category(tmp_path):
    captcha = CapturedFlow(
        method="POST",
        host="www.google.com",
        path="/recaptcha/api2/reload?k=site-key",
        url="https://www.google.com/recaptcha/api2/reload?k=site-key",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_body=b"v=abc",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b"{}",
    )
    flows_file = tmp_path / "flows.jsonl"
    flows_file.write_text(captcha.to_jsonl() + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec(
        "example.com",
        input_file=str(flows_file),
        output_file=str(output_file),
        include_hosts=["www.google.com"],
    )

    spec = yaml.safe_load(output_file.read_text())
    assert spec["paths"] == {}
    surface = json.loads((tmp_path / "openapi.surface.json").read_text())
    assert surface[0]["category"] == "captcha"
    assert surface[0]["included_in_openapi"] is False


def test_include_category_auth_adds_same_site_auth(tmp_path):
    auth = _flow(host="auth.example.com", path="/oauth/token")
    flows_file = tmp_path / "flows.jsonl"
    flows_file.write_text(auth.to_jsonl() + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec(
        "www.example.com",
        input_file=str(flows_file),
        output_file=str(output_file),
        include_categories=["auth"],
    )

    spec = yaml.safe_load(output_file.read_text())
    assert "/oauth/token" in spec["paths"]
    surface = json.loads((tmp_path / "openapi.surface.json").read_text())
    assert surface[0]["category"] == "auth"
    assert surface[0]["host_role"] == "same_site"


def test_stale_surface_metadata_falls_back_to_reclassification(tmp_path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    captcha = CapturedFlow(
        method="POST",
        host="www.google.com",
        path="/recaptcha/api2/reload?k=site-key",
        url="https://www.google.com/recaptcha/api2/reload?k=site-key",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_body=b"v=abc",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b"{}",
    )
    (bundle_dir / "flows.jsonl").write_text(captcha.to_jsonl() + "\n")
    (bundle_dir / "surface.jsonl").write_text(json.dumps({
        "flow_index": 0,
        "classification": {
            "classifier_version": "stale",
            "category": "business_api",
            "reason": "stale tag",
            "api_like": True,
            "host_role": "target",
            "signals": [],
        },
    }) + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec("example.com", input_file=str(bundle_dir), output_file=str(output_file))

    spec = yaml.safe_load(output_file.read_text())
    assert spec["paths"] == {}
    surface = json.loads((tmp_path / "openapi.surface.json").read_text())
    assert surface[0]["category"] == "captcha"


def test_context_mismatch_surface_metadata_falls_back_to_reclassification(tmp_path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    related = _flow(
        host="api.related.test",
        path="/v1/items",
        request_headers={"referer": "https://example.com/app"},
    )
    (bundle_dir / "flows.jsonl").write_text(related.to_jsonl() + "\n")
    (bundle_dir / "surface-context.json").write_text(json.dumps({
        "context_version": "capture-context-v1",
        "known_related_domains": [],
    }))
    (bundle_dir / "surface.jsonl").write_text(json.dumps({
        "flow_index": 0,
        "method": "GET",
        "host": "api.related.test",
        "path": "/v1/items",
        "capture_context": {
            "context_version": "capture-context-v1",
            "known_related_domains": [],
        },
        "classification": {
            "classifier_version": "surface-v1",
            "category": "business_api",
            "reason": "stale but current-version metadata",
            "api_like": True,
            "host_role": "target",
            "signals": [],
        },
    }) + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec("example.com", input_file=str(bundle_dir), output_file=str(output_file))

    spec = yaml.safe_load(output_file.read_text())
    assert spec["paths"] == {}
    surface = json.loads((tmp_path / "openapi.surface.json").read_text())
    assert surface[0]["category"] == "unknown_api_like"
    assert surface[0]["host_role"] == "same_site"


def test_malformed_surface_metadata_index_falls_back_to_reclassification(tmp_path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    flow = _flow(path="/api/users")
    (bundle_dir / "flows.jsonl").write_text(flow.to_jsonl() + "\n")
    context = {
        "context_version": "capture-context-v1",
        "known_related_domains": [],
    }
    (bundle_dir / "surface-context.json").write_text(json.dumps(context))
    (bundle_dir / "surface.jsonl").write_text(json.dumps({
        "flow_index": 1,
        "method": "GET",
        "host": "example.com",
        "path": "/api/users",
        "capture_context": context,
        "classification": {
            "classifier_version": "surface-v1",
            "category": "business_api",
            "reason": "out of range metadata",
            "api_like": True,
            "host_role": "target",
            "signals": [],
        },
    }) + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec("example.com", input_file=str(bundle_dir), output_file=str(output_file))

    spec = yaml.safe_load(output_file.read_text())
    assert "/api/users" in spec["paths"]


def test_surface_metadata_flow_identity_mismatch_falls_back_to_reclassification(tmp_path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    captcha = CapturedFlow(
        method="POST",
        host="www.google.com",
        path="/recaptcha/api2/reload?k=site-key",
        url="https://www.google.com/recaptcha/api2/reload?k=site-key",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_body=b"v=abc",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b"{}",
    )
    (bundle_dir / "flows.jsonl").write_text(captcha.to_jsonl() + "\n")
    context = {
        "context_version": "capture-context-v1",
        "known_related_domains": [],
    }
    (bundle_dir / "surface-context.json").write_text(json.dumps(context))
    (bundle_dir / "surface.jsonl").write_text(json.dumps({
        "flow_index": 0,
        "method": "GET",
        "host": "example.com",
        "path": "/api/users",
        "capture_context": context,
        "classification": {
            "classifier_version": "surface-v1",
            "category": "business_api",
            "reason": "stale metadata for another flow",
            "api_like": True,
            "host_role": "target",
            "signals": [],
        },
    }) + "\n")
    output_file = tmp_path / "openapi.yaml"

    run_spec("example.com", input_file=str(bundle_dir), output_file=str(output_file))

    spec = yaml.safe_load(output_file.read_text())
    assert spec["paths"] == {}
    surface = json.loads((tmp_path / "openapi.surface.json").read_text())
    assert surface[0]["category"] == "captcha"


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
        path="/",
        response_headers={"content-type": "text/html"},
        body=b"<html><body>Hello</body></html>",
    )
    assert is_api_flow(flow) is False


# ── Part B: Aggregation model tests ─────────────────────────────────


def test_query_param_observation_metadata_does_not_leak_values():
    f1 = _flow(path="/api/v1/users?token=secret-one&page=1")
    f2 = _flow(path="/api/v1/users?token=secret-two&sort=name")

    spec = generate_openapi([f1, f2], "example.com")

    params = {
        p["name"]: p
        for p in spec["paths"]["/api/v1/users"]["get"]["parameters"]
        if p["in"] == "query"
    }
    assert set(params) == {"page", "sort", "token"}
    assert params["token"]["required"] is False
    assert params["token"]["x-apisniff-observed"] == {
        "present_count": 2,
        "total_count": 2,
        "distinct_value_count": 2,
        "inferred_type": "string",
        "confidence": "observed",
    }
    assert params["page"]["x-apisniff-observed"]["present_count"] == 1
    assert params["sort"]["x-apisniff-observed"]["present_count"] == 1
    assert "secret-one" not in json.dumps(spec)
    assert "secret-two" not in json.dumps(spec)


def test_path_parameters_are_context_named_and_required():
    flow = _flow(path="/users/42/orders/7")

    spec = generate_openapi([flow], "example.com")

    operation = spec["paths"]["/users/{userId}/orders/{orderId}"]["get"]
    params = {p["name"]: p for p in operation["parameters"]}
    assert params["userId"]["in"] == "path"
    assert params["userId"]["required"] is True
    assert params["userId"]["schema"]["type"] == "integer"
    assert params["orderId"]["in"] == "path"
    assert params["orderId"]["required"] is True
    assert operation["operationId"] == "getUsersByUserIdOrdersByOrderId"


def test_path_singularization_avoids_nonsense_names():
    spec = generate_openapi([
        _flow(path="/business/1"),
        _flow(path="/addresses/2"),
        _flow(path="/statuses/3"),
    ], "example.com")

    assert "/business/{businessId}" in spec["paths"]
    assert "/addresses/{addressId}" in spec["paths"]
    assert "/statuses/{statusId}" in spec["paths"]


def test_operation_metadata_and_response_descriptions():
    f200 = _flow(path="/api/v1/users/1", status=200)
    f404 = _flow(path="/api/v1/users/2", status=404, body=b'{"error": "not found"}')

    spec = generate_openapi([f404, f200], "example.com")

    operation = spec["paths"]["/api/v1/users/{userId}"]["get"]
    assert operation["operationId"] == "getApiV1UsersByUserId"
    assert operation["tags"] == ["user"]
    assert operation["x-apisniff-observed"]["flow_count"] == 2
    assert operation["x-apisniff-observed"]["status_codes"] == [200, 404]
    assert operation["responses"]["200"]["description"] == "OK"
    assert operation["responses"]["404"]["description"] == "Not Found"


def test_generated_spec_order_is_deterministic_for_flow_order():
    flows = [
        _flow(
            "POST",
            "/api/v1/users",
            request_headers={"content-type": "application/json"},
            request_body=b"{}",
        ),
        _flow("GET", "/api/v1/assets/550e8400-e29b-41d4-a716-446655440000"),
        _flow("GET", "/api/v1/users?page=1"),
    ]

    spec_a = generate_openapi(flows, "example.com")
    spec_b = generate_openapi(list(reversed(flows)), "example.com")

    assert spec_a == spec_b


def test_generated_spec_nullable_fields_deterministic_for_flow_order():
    f1 = _flow(body=b'{"name": null, "id": 1}')
    f2 = _flow(body=b'{"name": "Alice", "id": 2}')

    spec_a = generate_openapi([f1, f2], "example.com")
    spec_b = generate_openapi([f2, f1], "example.com")

    assert spec_a == spec_b
    schema = _resp_schema(spec_a)
    assert schema["properties"]["name"]["nullable"] is True


def test_generated_spec_with_examples_is_deterministic_for_flow_order():
    flows = [
        _flow(body=b'{"id": 2, "name": "Bob"}'),
        _flow(body=b'{"name": "Alice", "id": 1}'),
    ]

    spec_a = generate_openapi(flows, "example.com", include_examples=True)
    spec_b = generate_openapi(list(reversed(flows)), "example.com", include_examples=True)

    assert spec_a == spec_b
    schema = _resp_schema(spec_a)
    assert list(schema["properties"]) == ["id", "name"]
    assert schema["properties"]["id"]["example"] == 1
    assert schema["properties"]["name"]["example"] == "Alice"


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


def test_component_promotion_preserves_security_schemes():
    flows = [
        _flow(path="/api/v1/users/1", body=b'{"id": 1, "name": "Alice"}'),
        _flow(path="/api/v1/customers/2", body=b'{"id": 2, "name": "Bob"}'),
    ]
    patterns = [AuthPattern(auth_type="bearer", detail="authorization: bearer", flow_count=2)]

    spec = generate_openapi(flows, "example.com", auth_patterns=patterns, infer_schemes=True)

    user_schema = (
        spec["paths"]["/api/v1/users/{userId}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]
    )
    customer_schema = (
        spec["paths"]["/api/v1/customers/{customerId}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]
    )
    assert user_schema == customer_schema
    assert user_schema["$ref"].startswith("#/components/schemas/")
    assert "schemas" in spec["components"]
    assert "securitySchemes" in spec["components"]


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
    flow = _flow(
        body=b'{"auth": "x", "author": "Jane", "secret": "s",'
        b' "secretariat": "UN", "token": "t", "max_tokens": 100}'
    )
    spec = generate_openapi([flow], "example.com", include_examples=True)

    props = _resp_schema(spec)["properties"]
    assert props["auth"]["example"] == "***REDACTED***"
    assert props["author"]["example"] == "Jane"
    assert props["secret"]["example"] == "***REDACTED***"
    assert props["secretariat"]["example"] == "UN"
    assert props["token"]["example"] == "***REDACTED***"
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

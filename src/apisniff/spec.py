from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from http.client import responses as http_responses
from pathlib import Path
from urllib.parse import parse_qs

import yaml
from rich.console import Console

from apisniff.auth import AuthPattern, detect_auth
from apisniff.bundle import load_flows, read_capture_jsonl
from apisniff.models import CapturedFlow, get_header
from apisniff.spec_classify import (
    OpenAPISelection,
    _target_host,
    build_capture_context,
    build_surface_inventory,
    classify_flows,
    classify_spec_flow,
    is_api_flow,
    is_spec_flow,
    select_openapi_flow,
    summarize_spec_selection,
)
from apisniff.spec_schema import (
    FILE_SENTINEL,
    _infer_json_body_schema,
    _infer_schema,
    _merge_schemas,
    _parse_form_urlencoded,
    _parse_json_body,
    _parse_multipart,
)
from apisniff.surface import (
    CAPTURE_CONTEXT_VERSION,
    read_capture_context,
    read_surface_metadata,
)

stderr = Console(stderr=True)

__all__ = [
    "_infer_schema",
    "_merge_schemas",
    "_parse_json_body",
    "build_surface_inventory",
    "classify_spec_flow",
    "generate_openapi",
    "is_api_flow",
    "is_spec_flow",
    "run_spec",
    "summarize_spec_selection",
]

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_NUMERIC_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_GENERIC_TAG_PREFIXES = frozenset({"api", "rest", "rpc"})
_VERSION_SEGMENT_RE = re.compile(r"^v\d+$", re.I)
_METHODS_WITH_REQUEST_BODY = frozenset({"post", "put", "patch"})


@dataclass(slots=True)
class QueryEvidence:
    present_count: int = 0
    values: set[str] = field(default_factory=set)


@dataclass(slots=True)
class ObservedOperation:
    path: str
    method: str
    flows: list[CapturedFlow] = field(default_factory=list)
    path_param_names: list[str] = field(default_factory=list)
    path_param_values: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    query: dict[str, QueryEvidence] = field(default_factory=lambda: defaultdict(QueryEvidence))
    request_schemas: dict[str, dict] = field(default_factory=dict)
    response_schemas: dict[tuple[str, str], dict] = field(default_factory=dict)


def _is_dynamic_path_segment(segment: str) -> bool:
    return bool(_UUID_RE.match(segment) or _NUMERIC_RE.match(segment) or _HEX_RE.match(segment))


def _singularize_segment(segment: str) -> str:
    lower = segment.lower()
    if lower == "statuses":
        return "status"
    if lower.endswith("sses") and len(segment) > 4:
        return segment[:-2]
    if lower.endswith("ies") and len(segment) > 4:
        return segment[:-3] + "y"
    if lower.endswith("s") and not lower.endswith(("ss", "us")) and len(segment) > 3:
        return segment[:-1]
    return segment


def _camel_name(value: str) -> str:
    parts = [part for part in re.split(r"[^0-9A-Za-z]+", value) if part]
    if not parts:
        return "param"
    first = parts[0].lower()
    return first + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def _pascal_name(value: str) -> str:
    if re.fullmatch(r"[A-Za-z][0-9A-Za-z]*", value) and any(char.isupper() for char in value):
        return value[:1].upper() + value[1:]
    camel = _camel_name(value)
    return camel[:1].upper() + camel[1:] if camel else "Value"


def _path_param_prefix(previous_static_segment: str | None) -> str:
    if not previous_static_segment:
        return "id"
    prefix = _singularize_segment(previous_static_segment)
    if len(prefix) < 3:
        prefix = previous_static_segment
    return _camel_name(prefix)


def _dedupe_param_name(base: str, counts: Counter[str]) -> str:
    counts[base] += 1
    if counts[base] == 1:
        return base
    return f"{base}{counts[base]}"


def _normalize_openapi_path(path: str) -> tuple[str, list[str], dict[str, str]]:
    path_only = path.split("?", 1)[0]
    parts = path_only.split("/")
    normalized: list[str] = []
    param_names: list[str] = []
    param_values: dict[str, str] = {}
    name_counts: Counter[str] = Counter()
    previous_static: str | None = None

    for part in parts:
        if not part:
            normalized.append(part)
            continue
        if _is_dynamic_path_segment(part):
            prefix = _path_param_prefix(previous_static)
            base_name = "id" if prefix == "id" else f"{prefix}Id"
            param_name = _dedupe_param_name(base_name, name_counts)
            normalized.append(f"{{{param_name}}}")
            param_names.append(param_name)
            param_values[param_name] = part
            continue
        normalized.append(part)
        previous_static = part

    normalized_path = "/".join(normalized)
    return normalized_path or "/", param_names, param_values


def _infer_primitive_type(values: set[str]) -> str:
    if not values:
        return "string"
    lowered = {value.lower() for value in values}
    if lowered <= {"true", "false"}:
        return "boolean"
    if all(re.fullmatch(r"[+-]?\d+", value) for value in values):
        return "integer"
    if all(re.fullmatch(r"[+-]?(\d+\.\d+|\d+|\.\d+)", value) for value in values):
        return "number"
    return "string"


def _operation_tag(path: str) -> str:
    for segment in (part for part in path.split("/") if part):
        if segment.startswith("{"):
            continue
        if segment.lower() in _GENERIC_TAG_PREFIXES or _VERSION_SEGMENT_RE.match(segment):
            continue
        return _singularize_segment(segment)
    return "default"


def _operation_id_base(method: str, path: str) -> str:
    parts: list[str] = [method.lower()]
    for segment in (part for part in path.split("/") if part):
        if segment.startswith("{") and segment.endswith("}"):
            parts.append("by")
            parts.append(segment[1:-1])
        else:
            parts.append(segment)
    first = _camel_name(parts[0])
    return first + "".join(_pascal_name(part) for part in parts[1:])


def _operation_ids(operations: list[ObservedOperation]) -> dict[tuple[str, str], str]:
    bases: dict[tuple[str, str], str] = {}
    counts: Counter[str] = Counter()
    for op in operations:
        base = _operation_id_base(op.method, op.path)
        bases[(op.path, op.method)] = base
        counts[base] += 1

    operation_ids: dict[tuple[str, str], str] = {}
    for op in operations:
        key = (op.path, op.method)
        base = bases[key]
        if counts[base] == 1:
            operation_ids[key] = base
            continue
        digest = hashlib.sha1(f"{op.method} {op.path}".encode()).hexdigest()[:8]
        operation_ids[key] = f"{base}_{digest}"
    return operation_ids


def _status_description(status_key: str) -> str:
    try:
        return http_responses[int(status_key)]
    except (KeyError, ValueError):
        return "Observed response"


def _record_request_schema(
    operation: ObservedOperation,
    flow: CapturedFlow,
    *,
    include_examples: bool,
) -> None:
    if operation.method not in _METHODS_WITH_REQUEST_BODY or not flow.request_body:
        return
    req_ct_raw = get_header(flow.request_headers, "content-type")
    req_ct = req_ct_raw.split(";")[0].strip().lower()

    new_schema: dict | None = None
    if req_ct == "application/json":
        new_schema = _infer_json_body_schema(flow.request_body, include_examples=include_examples)
    elif req_ct == "application/x-www-form-urlencoded":
        form_data = _parse_form_urlencoded(flow.request_body)
        if form_data is not None:
            new_schema = _infer_schema(form_data, include_examples=include_examples)
    elif req_ct == "multipart/form-data":
        mp_data = _parse_multipart(flow.request_body, req_ct_raw)
        if mp_data is not None:
            props: dict[str, dict] = {}
            for k, v in mp_data.items():
                if v == FILE_SENTINEL:
                    props[k] = {"type": "string", "format": "binary"}
                else:
                    props[k] = _infer_schema(v, include_examples=include_examples, field_name=k)
            new_schema = {"type": "object", "properties": props}

    if new_schema is None:
        return
    if req_ct in operation.request_schemas:
        operation.request_schemas[req_ct] = _merge_schemas(
            operation.request_schemas[req_ct],
            new_schema,
        )
    else:
        operation.request_schemas[req_ct] = new_schema


def _record_response_schema(
    operation: ObservedOperation,
    flow: CapturedFlow,
    *,
    include_examples: bool,
) -> None:
    resp_ct = flow.content_type or "application/json"
    if "json" not in resp_ct:
        return
    schema = _infer_json_body_schema(flow.response_body, include_examples=include_examples)
    if schema is None:
        return
    key = (str(flow.response_status), resp_ct)
    if key in operation.response_schemas:
        operation.response_schemas[key] = _merge_schemas(operation.response_schemas[key], schema)
    else:
        operation.response_schemas[key] = schema


def _aggregate_operations(
    flows: list[CapturedFlow],
    *,
    include_examples: bool,
) -> list[ObservedOperation]:
    operations: dict[tuple[str, str], ObservedOperation] = {}

    for flow in flows:
        path, param_names, param_values = _normalize_openapi_path(flow.path)
        method = flow.method.lower()
        key = (path, method)
        operation = operations.get(key)
        if operation is None:
            operation = ObservedOperation(path=path, method=method, path_param_names=param_names)
            operations[key] = operation
        operation.flows.append(flow)
        for name, value in param_values.items():
            operation.path_param_values[name].append(value)

        if "?" in flow.path:
            parsed_qs = parse_qs(flow.path.split("?", 1)[1], keep_blank_values=True)
            for param_name, values in parsed_qs.items():
                evidence = operation.query[param_name]
                evidence.present_count += 1
                evidence.values.update(values)

        _record_request_schema(operation, flow, include_examples=include_examples)
        _record_response_schema(operation, flow, include_examples=include_examples)

    return [operations[key] for key in sorted(operations)]


def _build_path_params(operation: ObservedOperation) -> list[dict]:
    params: list[dict] = []
    for name in operation.path_param_names:
        param_type = _infer_primitive_type(set(operation.path_param_values.get(name, [])))
        params.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": param_type},
        })
    return params


def _build_query_params(operation: ObservedOperation) -> list[dict]:
    params: list[dict] = []
    total = len(operation.flows)
    for name in sorted(operation.query):
        evidence = operation.query[name]
        inferred_type = _infer_primitive_type(evidence.values)
        params.append({
            "name": name,
            "in": "query",
            "required": False,
            "schema": {"type": inferred_type},
            "x-apisniff-observed": {
                "present_count": evidence.present_count,
                "total_count": total,
                "distinct_value_count": len(evidence.values),
                "inferred_type": inferred_type,
                "confidence": "observed",
            },
        })
    return params


def _build_request_body(operation: ObservedOperation) -> dict | None:
    if not operation.request_schemas:
        return None
    return {
        "content": {
            ct: {"schema": schema}
            for ct, schema in sorted(operation.request_schemas.items())
        }
    }


def _build_responses(operation: ObservedOperation) -> dict:
    statuses = {str(flow.response_status) for flow in operation.flows}
    responses: dict[str, dict] = {}
    for status in sorted(
        statuses,
        key=lambda value: (int(value) if value.isdigit() else 999, value),
    ):
        responses[status] = {"description": _status_description(status)}
    for (status, ct), schema in sorted(operation.response_schemas.items()):
        response = responses.setdefault(status, {"description": _status_description(status)})
        content = response.setdefault("content", {})
        content[ct] = {"schema": schema}
    if not responses:
        responses["default"] = {"description": "Observed response"}
    return responses


def _build_operation_metadata(operation: ObservedOperation, operation_id: str) -> dict:
    return {
        "operationId": operation_id,
        "tags": [_operation_tag(operation.path)],
        "x-apisniff-observed": {
            "flow_count": len(operation.flows),
            "hosts": sorted({flow.host.lower().rstrip(".") for flow in operation.flows}),
            "methods": sorted({flow.method.upper() for flow in operation.flows}),
            "status_codes": sorted({flow.response_status for flow in operation.flows}),
            "content_types": sorted({
                flow.content_type for flow in operation.flows if flow.content_type
            }),
        },
    }


def _schema_fingerprint(schema: dict) -> str:
    return json.dumps(schema, sort_keys=True, separators=(",", ":"))


def _component_base_name(path: str, context: str) -> str:
    static_segments = [
        segment
        for segment in path.split("/")
        if segment and not segment.startswith("{")
        and segment.lower() not in _GENERIC_TAG_PREFIXES
        and not _VERSION_SEGMENT_RE.match(segment)
    ]
    resource = _singularize_segment(static_segments[-1]) if static_segments else "Observed"
    return f"{_pascal_name(resource)}{context}"


def _unique_component_name(base: str, used: set[str]) -> str:
    candidate = base
    counter = 2
    while candidate in used:
        candidate = f"{base}{counter}"
        counter += 1
    used.add(candidate)
    return candidate


def _promote_components(spec: dict, operations: list[ObservedOperation]) -> None:
    candidates: dict[tuple[str, str], list[tuple[str, str, str, dict]]] = defaultdict(list)
    for operation in operations:
        methods = spec["paths"][operation.path]
        op_dict = methods[operation.method]
        request_body = op_dict.get("requestBody", {})
        for ct, media in request_body.get("content", {}).items():
            schema = media.get("schema", {})
            if schema.get("type") in {"object", "array"}:
                candidates[("Request", _schema_fingerprint(schema))].append(
                    (operation.path, operation.method, ct, schema)
                )
        for status, response in op_dict.get("responses", {}).items():
            for ct, media in response.get("content", {}).items():
                schema = media.get("schema", {})
                if schema.get("type") in {"object", "array"}:
                    candidates[("Response", _schema_fingerprint(schema))].append(
                        (operation.path, operation.method, f"{status}:{ct}", schema)
                    )

    components = spec.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    used_names = set(schemas)
    refs: dict[tuple[str, str], str] = {}
    for (context, fingerprint), uses in sorted(candidates.items()):
        if len(uses) < 2:
            continue
        path, _, _, schema = uses[0]
        name = _unique_component_name(_component_base_name(path, context), used_names)
        schemas[name] = schema
        refs[(context, fingerprint)] = f"#/components/schemas/{name}"

    if not refs:
        if not schemas:
            components.pop("schemas", None)
        if not components:
            spec.pop("components", None)
        return

    for operation in operations:
        op_dict = spec["paths"][operation.path][operation.method]
        request_body = op_dict.get("requestBody", {})
        for media in request_body.get("content", {}).values():
            schema = media.get("schema", {})
            ref = refs.get(("Request", _schema_fingerprint(schema)))
            if ref:
                media["schema"] = {"$ref": ref}
        for response in op_dict.get("responses", {}).values():
            for media in response.get("content", {}).values():
                schema = media.get("schema", {})
                ref = refs.get(("Response", _schema_fingerprint(schema)))
                if ref:
                    media["schema"] = {"$ref": ref}


def generate_openapi(
    flows: list[CapturedFlow],
    domain: str,
    auth_patterns: list[AuthPattern] | None = None,
    infer_schemes: bool = False,
    include_examples: bool = False,
) -> dict:
    host = _target_host(domain)
    operations = _aggregate_operations(flows, include_examples=include_examples)
    operation_ids = _operation_ids(operations)

    paths: dict[str, dict] = {}
    for operation in operations:
        op_dict: dict = _build_operation_metadata(
            operation,
            operation_ids[(operation.path, operation.method)],
        )
        parameters = _build_path_params(operation) + _build_query_params(operation)
        if parameters:
            op_dict["parameters"] = parameters
        request_body = _build_request_body(operation)
        if request_body:
            op_dict["requestBody"] = request_body
        op_dict["responses"] = _build_responses(operation)
        paths.setdefault(operation.path, {})[operation.method] = op_dict

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": f"{host} API",
            "version": "0.1.0",
            "description": f"Auto-generated from captured traffic for {domain}",
        },
        "servers": [{"url": f"https://{host}"}],
        "paths": paths,
    }

    if auth_patterns:
        x_observed: list[dict] = []
        x_token_endpoints: list[str] = []

        scheme_map = {
            "bearer": {"type": "http", "scheme": "bearer"},
            "api_key_header": lambda p: {"type": "apiKey", "in": "header", "name": p.detail},
            "api_key_query": lambda p: {"type": "apiKey", "in": "query", "name": p.detail},
            "session_cookie": lambda p: {"type": "apiKey", "in": "cookie", "name": p.detail},
        }

        schemes: dict[str, dict] = {}
        for pattern in auth_patterns:
            x_observed.append({
                "type": pattern.auth_type,
                "detail": pattern.detail,
                "flow_count": pattern.flow_count,
            })
            if pattern.auth_type == "token_endpoint":
                x_token_endpoints.append(pattern.detail)
                continue
            if infer_schemes:
                mapping = scheme_map.get(pattern.auth_type)
                if mapping is None:
                    continue
                schemes[pattern.auth_type] = (
                    mapping(pattern) if callable(mapping) else dict(mapping)
                )

        if schemes:
            spec.setdefault("components", {})["securitySchemes"] = schemes
        spec["x-observed-auth"] = x_observed
        if x_token_endpoints:
            spec["x-observed-token-endpoints"] = x_token_endpoints

    _promote_components(spec, operations)
    return spec


def run_spec(
    domain: str,
    input_file: str | None = None,
    output_format: str = "yaml",
    output_file: str | None = None,
    surface_output: str | None = None,
    infer_schemes: bool = False,
    include_examples: bool = False,
    include_third_party: bool = False,
    include_categories: list[str] | None = None,
    include_hosts: list[str] | None = None,
) -> None:
    bundle_dir: Path | None = None
    if input_file:
        input_path = Path(input_file)
        if input_path.is_dir():
            bundle_dir = input_path
            input_path = input_path / "flows.jsonl"
            if not input_path.exists():
                stderr.print(f"[red]flows.jsonl not found in {input_file}[/red]")
                raise SystemExit(1)
        try:
            flows, fmt = load_flows(str(input_path))
        except ValueError as e:
            stderr.print(f"[red]{e}[/red]")
            raise SystemExit(1) from None
        if fmt == "unknown":
            stderr.print(f"[red]Unknown input format for {input_file}[/red]")
            raise SystemExit(1)
    else:
        from apisniff.bundle import find_latest_bundle

        bundle = find_latest_bundle(domain)
        if bundle is None:
            stderr.print(
                f"[red]No captures found for {domain}. "
                f"Run `apisniff recon {domain}` first.[/red]"
            )
            return
        stderr.print(f"  Using latest capture: {bundle}")
        bundle_dir = bundle
        flows_path = bundle / "flows.jsonl"
        if not flows_path.exists():
            stderr.print(f"[red]flows.jsonl not found in {bundle}[/red]")
            return
        flows = read_capture_jsonl(str(flows_path))

    selection = OpenAPISelection(
        include_third_party=include_third_party,
        include_categories=frozenset(include_categories or ()),
        include_hosts=frozenset(
            host.lower().rstrip(".") for host in (include_hosts or ())
        ),
    )
    capture_context = read_capture_context(bundle_dir) if bundle_dir is not None else None
    current_context = build_capture_context(flows, domain)
    context_is_current = (
        capture_context is not None
        and capture_context.context_version == CAPTURE_CONTEXT_VERSION
        and capture_context == current_context
    )
    metadata = (
        read_surface_metadata(bundle_dir, capture_context, flows)
        if bundle_dir is not None and context_is_current
        else {}
    )
    if metadata and len(metadata) == len(flows):
        classifications = [metadata[index] for index in range(len(flows))]
    elif context_is_current:
        classifications = classify_flows(flows, domain, capture_context)
    else:
        classifications = classify_flows(flows, domain, current_context)
    api_flows = [
        flow
        for flow, classification in zip(flows, classifications, strict=True)
        if select_openapi_flow(flow, classification, domain, selection)
    ]
    selection_summary = summarize_spec_selection(
        flows,
        domain,
        classifications,
        selection,
    )

    auth_patterns = detect_auth(api_flows)
    spec = generate_openapi(
        api_flows,
        domain,
        auth_patterns=auth_patterns,
        infer_schemes=infer_schemes,
        include_examples=include_examples,
    )

    if output_format == "json":
        output = json.dumps(spec, indent=2)
    else:
        output = yaml.dump(spec, sort_keys=False, default_flow_style=False)

    if output_file:
        output_path = Path(output_file)
        output_path.write_text(output)
        stderr.print(f"  Spec written to {output_file}")
    else:
        sys.stdout.write(output)

    surface_path: Path | None = Path(surface_output) if surface_output else None
    if surface_path is None and output_file:
        output_path = Path(output_file)
        surface_path = output_path.with_name(f"{output_path.stem}.surface.json")
    if surface_path is not None:
        inventory = build_surface_inventory(flows, domain, classifications, selection)
        surface_path.write_text(json.dumps(inventory, indent=2))
        stderr.print(f"  Surface inventory written to {surface_path}")

    endpoint_count = sum(len(methods) for methods in spec["paths"].values())
    stderr.print(
        f"\n  [bold]{len(spec['paths'])}[/bold] paths, "
        f"[bold]{endpoint_count}[/bold] operations"
    )
    excluded_by_category = {
        category: counts["excluded"]
        for category, counts in selection_summary["categories"].items()
        if counts["excluded"]
    }
    if excluded_by_category:
        formatted = ", ".join(
            f"{category}: {count}" for category, count in sorted(excluded_by_category.items())
        )
        stderr.print(f"  Excluded from OpenAPI: {formatted}")

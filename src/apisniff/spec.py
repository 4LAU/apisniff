# src/apisniff/spec.py
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml
from rich.console import Console

from apisniff.auth import AuthPattern, detect_auth
from apisniff.bundle import load_flows, read_capture_jsonl
from apisniff.models import CapturedFlow, normalize_path

stderr = Console(stderr=True)

_MULTIPART_NAME_RE = re.compile(r'name="([^"]+)"')
_MULTIPART_FILENAME_RE = re.compile(r'filename="[^"]*"')
_SECRET_RE = re.compile(r"(?i)^(bearer |eyj|sk_|pk_|api_|ghp_|gho_|xox[bpsar]-|AKIA)")
_MAX_EXAMPLE_LEN = 200

_API_CONTENT_TYPES = frozenset({
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
})


def _get_header_ci(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup. Returns '' if not found."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return ""


def _is_api_flow(flow: CapturedFlow) -> bool:
    """Return True if flow is API traffic worth including in a spec."""
    resp_ct = _get_header_ci(flow.response_headers, "content-type").split(";")[0].strip().lower()
    if "json" in resp_ct:
        return True
    req_ct = _get_header_ci(flow.request_headers, "content-type").split(";")[0].strip().lower()
    if req_ct in _API_CONTENT_TYPES:
        return True
    return False


def _redact_if_secret(value: str) -> str:
    """Replace values that look like secrets with '***REDACTED***'."""
    if _SECRET_RE.search(value):
        return "***REDACTED***"
    return value


def _infer_schema(value, *, include_examples: bool = False) -> dict:
    if value is None:
        return {"type": "string", "nullable": True}
    if isinstance(value, bool):
        schema: dict = {"type": "boolean"}
        if include_examples:
            schema["example"] = value
        return schema
    if isinstance(value, int):
        schema = {"type": "integer"}
        if include_examples:
            schema["example"] = value
        return schema
    if isinstance(value, float):
        schema = {"type": "number"}
        if include_examples:
            schema["example"] = value
        return schema
    if isinstance(value, str):
        schema = {"type": "string"}
        if include_examples:
            redacted = _redact_if_secret(value)
            if len(redacted) > _MAX_EXAMPLE_LEN:
                redacted = redacted[:_MAX_EXAMPLE_LEN] + "..."
            schema["example"] = redacted
        return schema
    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        return {"type": "array", "items": _infer_schema(value[0], include_examples=include_examples)}
    if isinstance(value, dict):
        properties = {}
        for k, v in value.items():
            properties[k] = _infer_schema(v, include_examples=include_examples)
        return {"type": "object", "properties": properties}
    return {"type": "string"}


def _parse_response_body(body: bytes) -> dict | None:
    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _parse_form_urlencoded(body: bytes) -> dict | None:
    """Parse URL-encoded form body into a dict suitable for schema inference."""
    if not body:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parsed = parse_qs(text, keep_blank_values=True)
    if not parsed:
        return None
    result: dict[str, str] = {}
    for k, vals in parsed.items():
        result[k] = vals[0] if vals else ""
    return result


def _parse_multipart(body: bytes, content_type: str) -> dict | None:
    """Parse multipart form-data body into a dict for schema inference.

    File fields (those with filename=) get value "__file__" so downstream
    schema inference can mark them as format: binary.
    """
    if not body:
        return None
    # Extract boundary from content-type header
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            boundary = part[len("boundary="):]
            break
    if not boundary:
        return None

    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return None

    result: dict = {}
    # Split on boundary markers
    parts = text.split(f"--{boundary}")
    for segment in parts:
        name_m = _MULTIPART_NAME_RE.search(segment)
        if not name_m:
            continue
        field_name = name_m.group(1)
        is_file = bool(_MULTIPART_FILENAME_RE.search(segment))
        if is_file:
            result[field_name] = "__file__"
        else:
            # Value is after the double newline in the part
            header_body = segment.split("\r\n\r\n", 1)
            if len(header_body) < 2:
                header_body = segment.split("\n\n", 1)
            val = header_body[1].strip().rstrip("-") if len(header_body) >= 2 else ""
            result[field_name] = val
    return result if result else None


def _merge_schemas(existing: dict, new: dict) -> dict:
    """Recursively merge two JSON schemas, keeping the union of properties."""
    if not existing:
        return new
    if not new:
        return existing

    e_type = existing.get("type")
    n_type = new.get("type")

    # If types differ, prefer the one that has more info
    if e_type != n_type:
        # Prefer object/array over string/empty
        if n_type in ("object", "array") and e_type not in ("object", "array"):
            return new
        return existing

    if e_type == "object":
        merged_props = dict(existing.get("properties", {}))
        for k, v in new.get("properties", {}).items():
            if k in merged_props:
                merged_props[k] = _merge_schemas(merged_props[k], v)
            else:
                merged_props[k] = v
        result = dict(existing)
        result["properties"] = merged_props
        return result

    if e_type == "array":
        e_items = existing.get("items", {})
        n_items = new.get("items", {})
        # Empty array enriched by populated array
        if not e_items and n_items:
            result = dict(existing)
            result["items"] = n_items
            return result
        if e_items and n_items:
            result = dict(existing)
            result["items"] = _merge_schemas(e_items, n_items)
            return result
        return existing

    return existing


def generate_openapi(
    flows: list[CapturedFlow],
    domain: str,
    auth_patterns: list[AuthPattern] | None = None,
    infer_schemes: bool = False,
    include_examples: bool = False,
) -> dict:
    # Phase 1: Group flows by (normalized_path, method)
    groups: dict[tuple[str, str], list[CapturedFlow]] = defaultdict(list)
    for flow in flows:
        norm_path = normalize_path(flow.path)
        method = flow.method.lower()
        groups[(norm_path, method)].append(flow)

    paths: dict[str, dict] = defaultdict(dict)

    for (norm_path, method), group in groups.items():
        operation: dict = {"responses": {}}

        # --- Aggregate query params across ALL flows ---
        seen_params: dict[str, dict] = {}
        for flow in group:
            if "?" in flow.path:
                qs = flow.path.split("?", 1)[1]
                parsed_qs = parse_qs(qs, keep_blank_values=True)
                for param_name in parsed_qs:
                    if param_name not in seen_params:
                        seen_params[param_name] = {
                            "name": param_name,
                            "in": "query",
                            "schema": {"type": "string"},
                        }
        if seen_params:
            operation["parameters"] = list(seen_params.values())

        # --- Aggregate responses per status code ---
        response_schemas: dict[str, dict] = {}
        for flow in group:
            status_key = str(flow.response_status)
            parsed = _parse_response_body(flow.response_body)
            if status_key not in operation["responses"]:
                operation["responses"][status_key] = {
                    "description": "Observed response",
                }
            if parsed is not None:
                new_schema = _infer_schema(parsed, include_examples=include_examples)
                if status_key in response_schemas:
                    response_schemas[status_key] = _merge_schemas(
                        response_schemas[status_key], new_schema
                    )
                else:
                    response_schemas[status_key] = new_schema

        for status_key, schema in response_schemas.items():
            operation["responses"][status_key]["content"] = {
                "application/json": {"schema": schema}
            }

        # --- Aggregate request bodies per content type ---
        if method in ("post", "put", "patch"):
            request_content: dict[str, dict] = {}
            for flow in group:
                if not flow.request_body:
                    continue
                req_ct_raw = _get_header_ci(flow.request_headers, "content-type")
                req_ct = req_ct_raw.split(";")[0].strip().lower()

                if req_ct == "application/json":
                    req_parsed = _parse_response_body(flow.request_body)
                    if req_parsed is not None:
                        new_schema = _infer_schema(req_parsed, include_examples=include_examples)
                        ct_key = "application/json"
                        if ct_key in request_content:
                            request_content[ct_key]["schema"] = _merge_schemas(
                                request_content[ct_key]["schema"], new_schema
                            )
                        else:
                            request_content[ct_key] = {"schema": new_schema}

                elif req_ct == "application/x-www-form-urlencoded":
                    form_data = _parse_form_urlencoded(flow.request_body)
                    if form_data is not None:
                        new_schema = _infer_schema(form_data, include_examples=include_examples)
                        ct_key = "application/x-www-form-urlencoded"
                        if ct_key in request_content:
                            request_content[ct_key]["schema"] = _merge_schemas(
                                request_content[ct_key]["schema"], new_schema
                            )
                        else:
                            request_content[ct_key] = {"schema": new_schema}

                elif req_ct == "multipart/form-data":
                    mp_data = _parse_multipart(flow.request_body, req_ct_raw)
                    if mp_data is not None:
                        # Build schema manually for multipart: file fields get format: binary
                        props: dict[str, dict] = {}
                        for k, v in mp_data.items():
                            if v == "__file__":
                                props[k] = {"type": "string", "format": "binary"}
                            else:
                                props[k] = _infer_schema(v, include_examples=include_examples)
                        new_schema = {"type": "object", "properties": props}
                        ct_key = "multipart/form-data"
                        if ct_key in request_content:
                            request_content[ct_key]["schema"] = _merge_schemas(
                                request_content[ct_key]["schema"], new_schema
                            )
                        else:
                            request_content[ct_key] = {"schema": new_schema}

            if request_content:
                operation["requestBody"] = {"content": request_content}

        paths[norm_path][method] = operation

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": f"{domain} API",
            "version": "0.1.0",
            "description": f"Auto-generated from captured traffic for {domain}",
        },
        "servers": [{"url": f"https://{domain}"}],
        "paths": dict(paths),
    }

    if auth_patterns:
        x_observed: list[dict] = []
        x_token_endpoints: list[str] = []

        _SCHEME_MAP = {
            "bearer": {"type": "http", "scheme": "bearer"},
            "api_key_header": lambda p: {"type": "apiKey", "in": "header", "name": p.detail},
            "api_key_query": lambda p: {"type": "apiKey", "in": "query", "name": p.detail},
            "session_cookie": lambda p: {"type": "apiKey", "in": "cookie", "name": p.detail},
        }

        schemes: dict[str, dict] = {}
        for p in auth_patterns:
            x_observed.append({"type": p.auth_type, "detail": p.detail, "flow_count": p.flow_count})
            if p.auth_type == "token_endpoint":
                x_token_endpoints.append(p.detail)
                continue
            if infer_schemes:
                mapping = _SCHEME_MAP.get(p.auth_type)
                if mapping is None:
                    continue
                if callable(mapping):
                    schemes[p.auth_type] = mapping(p)
                else:
                    schemes[p.auth_type] = dict(mapping)

        if schemes:
            spec["components"] = {"securitySchemes": schemes}
        spec["x-observed-auth"] = x_observed
        if x_token_endpoints:
            spec["x-observed-token-endpoints"] = x_token_endpoints

    return spec


def run_spec(
    domain: str,
    input_file: str | None = None,
    output_format: str = "yaml",
    output_file: str | None = None,
    infer_schemes: bool = False,
    include_examples: bool = False,
) -> None:
    if input_file:
        flows, fmt = load_flows(input_file)
        if fmt == "unknown":
            stderr.print(f"[red]Unknown input format for {input_file}[/red]")
            return
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
        flows_path = bundle / "flows.jsonl"
        if not flows_path.exists():
            stderr.print(f"[red]flows.jsonl not found in {bundle}[/red]")
            return
        flows = read_capture_jsonl(str(flows_path))

    api_flows = [f for f in flows if _is_api_flow(f)]

    auth_patterns = detect_auth(flows)
    spec = generate_openapi(
        api_flows, domain,
        auth_patterns=auth_patterns, infer_schemes=infer_schemes,
        include_examples=include_examples,
    )

    if output_format == "json":
        output = json.dumps(spec, indent=2)
    else:
        output = yaml.dump(spec, sort_keys=False, default_flow_style=False)

    if output_file:
        Path(output_file).write_text(output)
        stderr.print(f"  Spec written to {output_file}")
    else:
        sys.stdout.write(output)

    endpoint_count = sum(len(methods) for methods in spec["paths"].values())
    stderr.print(
        f"\n  [bold]{len(spec['paths'])}[/bold] paths, "
        f"[bold]{endpoint_count}[/bold] operations"
    )

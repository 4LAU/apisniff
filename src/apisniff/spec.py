# src/apisniff/spec.py
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from rich.console import Console

from apisniff.auth import AuthPattern, detect_auth
from apisniff.models import CapturedFlow, normalize_path
from apisniff.recon import load_flows, read_capture_jsonl

stderr = Console(stderr=True)


def _infer_schema(value) -> dict:
    if value is None:
        return {"type": "string", "nullable": True}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        return {"type": "array", "items": _infer_schema(value[0])}
    if isinstance(value, dict):
        properties = {}
        for k, v in value.items():
            properties[k] = _infer_schema(v)
        return {"type": "object", "properties": properties}
    return {"type": "string"}


def _parse_response_body(body: bytes) -> dict | None:
    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def generate_openapi(
    flows: list[CapturedFlow],
    domain: str,
    auth_patterns: list[AuthPattern] | None = None,
    infer_schemes: bool = False,
) -> dict:
    paths: dict[str, dict] = defaultdict(dict)

    for flow in flows:
        norm_path = normalize_path(flow.path)
        method = flow.method.lower()

        if method in paths[norm_path]:
            continue

        operation: dict = {
            "responses": {
                str(flow.response_status): {
                    "description": "Observed response",
                }
            }
        }

        parsed = _parse_response_body(flow.response_body)
        if parsed is not None:
            schema = _infer_schema(parsed)
            operation["responses"][str(flow.response_status)]["content"] = {
                "application/json": {"schema": schema}
            }

        if method in ("post", "put", "patch") and flow.request_body:
            req_parsed = _parse_response_body(flow.request_body)
            if req_parsed is not None:
                operation["requestBody"] = {
                    "content": {
                        "application/json": {
                            "schema": _infer_schema(req_parsed)
                        }
                    }
                }

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
) -> None:
    if input_file:
        flows, fmt = load_flows(input_file)
        if fmt == "unknown":
            stderr.print(f"[red]Unknown input format for {input_file}[/red]")
            return
    else:
        from apisniff.recon import find_latest_bundle

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

    api_flows = [
        f for f in flows
        if "json" in (f.content_type or "") and 200 <= f.response_status < 300
    ]

    auth_patterns = detect_auth(flows)
    spec = generate_openapi(
        api_flows, domain,
        auth_patterns=auth_patterns, infer_schemes=infer_schemes,
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

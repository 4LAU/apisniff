# src/apisniff/spec.py
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

import yaml
from rich.console import Console

from apisniff.adapters.har import har_to_flows
from apisniff.models import CapturedFlow
from apisniff.recon import detect_input_format, read_capture_jsonl

console = Console()

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_NUMERIC_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def _normalize_path(path: str) -> str:
    parts = path.split("?")[0].split("/")
    normalized = []
    for part in parts:
        if not part:
            normalized.append(part)
            continue
        if _UUID_RE.match(part) or _NUMERIC_RE.match(part) or _HEX_RE.match(part):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/".join(normalized)


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


def generate_openapi(flows: list[CapturedFlow], domain: str) -> dict:
    paths: dict[str, dict] = defaultdict(dict)

    for flow in flows:
        if flow.response_status == 0:
            continue

        norm_path = _normalize_path(flow.path)
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

    return {
        "openapi": "3.0.3",
        "info": {
            "title": f"{domain} API",
            "version": "0.1.0",
            "description": f"Auto-generated from captured traffic for {domain}",
        },
        "servers": [{"url": f"https://{domain}"}],
        "paths": dict(paths),
    }


def run_spec(
    domain: str,
    input_file: str | None = None,
    output_format: str = "yaml",
    output_file: str | None = None,
) -> None:
    if input_file:
        path = Path(input_file)
        with open(path) as f:
            first_line = f.readline()
        fmt = detect_input_format(first_line)
        if fmt == "har":
            flows = har_to_flows(path.read_text())
        elif fmt == "jsonl":
            flows = read_capture_jsonl(str(path))
        else:
            console.print(f"[red]Unknown input format for {input_file}[/red]")
            return
    else:
        from apisniff.recon import _CAPTURES_DIR

        pattern = f"{domain.replace('.', '-')}*.jsonl"
        captures = sorted(_CAPTURES_DIR.glob(pattern), reverse=True)
        if not captures:
            console.print(
                f"[red]No captures found for {domain}. "
                f"Run `apisniff recon {domain}` first.[/red]"
            )
            return
        latest = captures[0]
        console.print(f"  Using latest capture: {latest}")
        flows = read_capture_jsonl(str(latest))

    api_flows = [f for f in flows if f.content_type in ("application/json", "")]

    spec = generate_openapi(api_flows, domain)

    if output_format == "json":
        output = json.dumps(spec, indent=2)
    else:
        output = yaml.dump(spec, sort_keys=False, default_flow_style=False)

    if output_file:
        Path(output_file).write_text(output)
        console.print(f"  Spec written to {output_file}")
    else:
        console.print(output)

    endpoint_count = sum(len(methods) for methods in spec["paths"].values())
    console.print(
        f"\n  [bold]{len(spec['paths'])}[/bold] paths, "
        f"[bold]{endpoint_count}[/bold] operations"
    )

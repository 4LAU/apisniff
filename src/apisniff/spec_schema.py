from __future__ import annotations

import json
import re
from urllib.parse import parse_qs

_MULTIPART_NAME_RE = re.compile(r'name="([^"]+)"')
_MULTIPART_FILENAME_RE = re.compile(r'filename="[^"]*"')
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_NUMERIC_RE = re.compile(r"^\d+$")
_SECRET_RE = re.compile(
    r"(?i)(bearer |basic |eyj|sk_|pk_|api_|ghp_|gho_|ghs_|glpat-|xox[bpsar]-|AKIA)"
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(password|passwd|(^|_)secret(_|$)|credential|api_?key|private_?key"
    r"|access_?token|refresh_?token|client_?secret|\bauth\b|auth_"
    r"|(^|_)token(_|$)|ssn|social_?security)"
)

MAX_BODY_SIZE = 1_000_000
MAX_SCHEMA_DEPTH = 20
MAX_EXAMPLE_LEN = 200
FILE_SENTINEL = "__file__"


def _redact_if_secret(value: str) -> str:
    """Replace values that look like secrets with '***REDACTED***'."""
    if _SECRET_RE.search(value):
        return "***REDACTED***"
    return value


def _schema_with_truncation(schema: dict) -> dict:
    result = dict(schema)
    result["x-apisniff-truncated"] = True
    return result


def _observed_types(*schemas: dict) -> list[str]:
    observed: set[str] = set()
    for schema in schemas:
        schema_type = schema.get("type")
        if isinstance(schema_type, str):
            observed.add(schema_type)
        observed.update(schema.get("x-apisniff-observed-types", []))
    return sorted(observed)


def _example_sort_key(value) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return repr(value)


def _merge_examples(existing: dict, new: dict, result: dict) -> None:
    examples = [
        schema["example"]
        for schema in (existing, new)
        if isinstance(schema, dict) and "example" in schema
    ]
    if examples:
        result["example"] = min(examples, key=_example_sort_key)


def _merge_additional_properties(existing, new):
    if existing is True or new is True:
        if isinstance(existing, dict):
            return existing
        if isinstance(new, dict):
            return new
        return True
    if isinstance(existing, dict) and isinstance(new, dict):
        return _merge_schemas(existing, new)
    if isinstance(existing, dict):
        return existing
    if isinstance(new, dict):
        return new
    return True


def _is_map_key(key: str) -> bool:
    return bool(_NUMERIC_RE.match(key) or _UUID_RE.match(key))


def _infer_schema(
    value,
    *,
    include_examples: bool = False,
    field_name: str = "",
    max_depth: int = MAX_SCHEMA_DEPTH,
    _depth: int = 0,
) -> dict:
    if _depth >= max_depth:
        if isinstance(value, dict):
            return _schema_with_truncation({"type": "object", "additionalProperties": True})
        if isinstance(value, list):
            return _schema_with_truncation({"type": "array", "items": {}})
        return _schema_with_truncation({"type": "string"})

    if value is None:
        return {"type": "string", "nullable": True}
    sensitive = bool(field_name and _SENSITIVE_FIELD_RE.search(field_name))
    if isinstance(value, bool):
        schema: dict = {"type": "boolean"}
        if include_examples:
            schema["example"] = "***REDACTED***" if sensitive else value
        return schema
    if isinstance(value, int):
        schema = {"type": "integer"}
        if include_examples:
            schema["example"] = "***REDACTED***" if sensitive else value
        return schema
    if isinstance(value, float):
        schema = {"type": "number"}
        if include_examples:
            schema["example"] = "***REDACTED***" if sensitive else value
        return schema
    if isinstance(value, str):
        schema = {"type": "string"}
        if include_examples:
            redacted = "***REDACTED***" if sensitive else _redact_if_secret(value)
            if len(redacted) > MAX_EXAMPLE_LEN:
                redacted = redacted[:MAX_EXAMPLE_LEN] + "..."
            schema["example"] = redacted
        return schema
    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        item_schema: dict = {}
        for item in value:
            item_schema = _merge_schemas(
                item_schema,
                _infer_schema(
                    item,
                    include_examples=include_examples,
                    field_name=field_name,
                    max_depth=max_depth,
                    _depth=_depth + 1,
                ),
            )
        return {"type": "array", "items": item_schema}
    if isinstance(value, dict):
        if value and all(_is_map_key(str(k)) for k in value):
            additional_schema: dict = {}
            for v in value.values():
                additional_schema = _merge_schemas(
                    additional_schema,
                    _infer_schema(
                        v,
                        include_examples=include_examples,
                        field_name=field_name,
                        max_depth=max_depth,
                        _depth=_depth + 1,
                    ),
                )
            return {"type": "object", "additionalProperties": additional_schema or True}

        properties = {}
        for k, v in sorted(value.items()):
            properties[k] = _infer_schema(
                v,
                include_examples=include_examples,
                field_name=k,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        return {"type": "object", "properties": properties}
    return {"type": "string"}


def _parse_json_body(body: bytes) -> dict | list | None:
    if not body:
        return None
    if len(body) > MAX_BODY_SIZE:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _infer_json_body_schema(body: bytes, *, include_examples: bool = False) -> dict | None:
    if not body:
        return None
    if len(body) > MAX_BODY_SIZE:
        return _schema_with_truncation({"type": "string"})
    parsed = _parse_json_body(body)
    if parsed is None:
        return None
    return _infer_schema(parsed, include_examples=include_examples)


def _parse_form_urlencoded(body: bytes) -> dict | None:
    """Parse URL-encoded form body into a dict suitable for schema inference."""
    if not body:
        return None
    if len(body) > MAX_BODY_SIZE:
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
    if len(body) > MAX_BODY_SIZE:
        return None
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            boundary = part[len("boundary="):]
            break
    if not boundary:
        return None

    text = body.decode("utf-8", errors="replace")

    result: dict = {}
    parts = text.split(f"--{boundary}")
    for segment in parts:
        name_m = _MULTIPART_NAME_RE.search(segment)
        if not name_m:
            continue
        field_name = name_m.group(1)
        is_file = bool(_MULTIPART_FILENAME_RE.search(segment))
        if is_file:
            result[field_name] = FILE_SENTINEL
        else:
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

    if e_type != n_type:
        if n_type in ("object", "array") and e_type not in ("object", "array"):
            return new
        if e_type in ("object", "array") and n_type not in ("object", "array"):
            return existing
        result: dict = {"type": "string"}
        observed = _observed_types(existing, new)
        if observed:
            result["x-apisniff-observed-types"] = observed
        if existing.get("x-apisniff-truncated") or new.get("x-apisniff-truncated"):
            result["x-apisniff-truncated"] = True
        return result

    if e_type == "object":
        result = dict(existing)
        if "additionalProperties" in existing or "additionalProperties" in new:
            result["additionalProperties"] = _merge_additional_properties(
                existing.get("additionalProperties", {}),
                new.get("additionalProperties", {}),
            )
            result.pop("properties", None)
        else:
            merged_props = dict(existing.get("properties", {}))
            for k, v in sorted(new.get("properties", {}).items()):
                if k in merged_props:
                    merged_props[k] = _merge_schemas(merged_props[k], v)
                else:
                    merged_props[k] = v
            result["properties"] = dict(sorted(merged_props.items()))
        if existing.get("x-apisniff-truncated") or new.get("x-apisniff-truncated"):
            result["x-apisniff-truncated"] = True
        return result

    if e_type == "array":
        e_items = existing.get("items", {})
        n_items = new.get("items", {})
        result = dict(existing)
        if not e_items and n_items:
            result["items"] = n_items
            return result
        if e_items and n_items:
            result["items"] = _merge_schemas(e_items, n_items)
            return result
        return existing

    result = dict(existing)
    _merge_examples(existing, new, result)
    if existing.get("x-apisniff-truncated") or new.get("x-apisniff-truncated"):
        result["x-apisniff-truncated"] = True
    observed = _observed_types(existing, new)
    if len(observed) > 1:
        result["x-apisniff-observed-types"] = observed
    return result

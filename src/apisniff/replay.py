from __future__ import annotations

import asyncio
import fnmatch
import json
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from apisniff.bundle import find_latest_bundle, read_capture_jsonl
from apisniff.models import (
    CapturedFlow,
    ReplayAbort,
    ReplayCategory,
    ReplayResult,
    replay_dedup_key,
)

_HOP_BY_HOP = frozenset(
    {"host", "content-length", "content-encoding", "transfer-encoding"}
)
_AUTH_HEADERS = frozenset(
    {"authorization", "cookie", "x-api-key", "api-key", "apikey"}
)
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_DEPTH = 3


def _shape(value: Any, depth: int) -> Any:
    """Return a structural shape descriptor for a JSON value."""
    if depth <= 0:
        return type(value).__name__
    if isinstance(value, dict):
        return {k: _shape(v, depth - 1) for k, v in value.items()}
    if isinstance(value, list):
        if not value:
            return []
        first_shape = _shape(value[0], depth - 1)
        first_type = type(value[0]).__name__
        for item in value[1:]:
            if type(item).__name__ != first_type:
                return ["mixed"]
        return [first_shape]
    return type(value).__name__


def _diff_shapes(original: Any, replayed: Any, path: str = "") -> dict:
    """Recursively diff two shape descriptors. Returns dict of {path: change}."""
    diffs: dict[str, Any] = {}

    if type(original) is not type(replayed):
        diffs[path or "root"] = {"was": original, "now": replayed}
        return diffs

    if isinstance(original, dict) and isinstance(replayed, dict):
        all_keys = set(original) | set(replayed)
        for key in all_keys:
            child_path = f"{path}.{key}" if path else key
            if key not in original:
                diffs[child_path] = {"was": None, "now": replayed[key]}
            elif key not in replayed:
                diffs[child_path] = {"was": original[key], "now": None}
            else:
                child_diffs = _diff_shapes(original[key], replayed[key], child_path)
                diffs.update(child_diffs)
        return diffs

    if original != replayed:
        diffs[path or "root"] = {"was": original, "now": replayed}

    return diffs


def compare_shape(
    original_body: bytes,
    replayed_body: bytes,
) -> tuple[bool, dict | None]:
    """Compare JSON body shapes up to depth 3.

    Returns (body_shape_match, body_shape_diff).
    """
    orig_json: Any = None
    repl_json: Any = None
    orig_parsed = False
    repl_parsed = False

    if original_body:
        try:
            orig_json = json.loads(original_body)
            orig_parsed = True
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    if replayed_body:
        try:
            repl_json = json.loads(replayed_body)
            repl_parsed = True
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    if orig_parsed != repl_parsed:
        return False, {"json_parse_mismatch": {"was": orig_parsed, "now": repl_parsed}}

    # Neither parses as JSON — treat as matching (binary/text blobs, no shape)
    if not orig_parsed and not repl_parsed:
        return True, None

    orig_shape = _shape(orig_json, _MAX_DEPTH)
    repl_shape = _shape(repl_json, _MAX_DEPTH)

    diffs = _diff_shapes(orig_shape, repl_shape)
    if diffs:
        return False, diffs
    return True, None


def parse_cookie_file(path: str) -> list[tuple[str, str, str]]:
    """Parse Netscape cookies.txt. Returns list of (domain, name, value)."""
    results: list[tuple[str, str, str]] = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            results.append((parts[0], parts[5], parts[6]))
    return results


def cookies_for_host(
    cookies: list[tuple[str, str, str]],
    host: str,
) -> str:
    """Return Cookie header value for cookies matching host."""
    matching: list[str] = []
    for domain, name, value in cookies:
        if domain.startswith("."):
            # Suffix match: .example.com matches api.example.com and example.com
            suffix = domain[1:]
            if host == suffix or host.endswith("." + suffix):
                matching.append(f"{name}={value}")
        else:
            # Exact match
            if host == domain:
                matching.append(f"{name}={value}")
    return "; ".join(matching)


def _request_host(flow: CapturedFlow) -> str:
    host = (urlparse(flow.url).hostname or "").lower()
    expected = flow.host.lower()
    if not host:
        return expected
    if expected and host != expected:
        raise ValueError(
            f"flow host mismatch: host={flow.host!r}, url host={host!r}"
        )
    return host


def _has_auth_headers(flow: CapturedFlow) -> bool:
    lower_keys = {k.lower() for k in flow.request_headers}
    return bool(lower_keys & _AUTH_HEADERS)


def _assign_category(
    flow: CapturedFlow,
    replayed_status: int | None,
    body_shape_match: bool,
    size_original: int,
    size_replayed: int,
    error: str | None,
) -> tuple[ReplayCategory, bool]:
    """Return (category, status_match)."""
    if error or replayed_status is None:
        return "error", False

    status_match = flow.response_status == replayed_status
    orig_2xx = 200 <= flow.response_status < 300

    if replayed_status in (401, 403) and orig_2xx:
        if _has_auth_headers(flow):
            return "auth_expired", status_match
        return "blocked", status_match

    if replayed_status in (403, 429, 503) and orig_2xx and not _has_auth_headers(flow):
        return "blocked", status_match

    if not status_match:
        return "drift", status_match

    if not body_shape_match:
        return "drift", status_match

    if size_original > 0:
        size_delta = abs(size_replayed - size_original) / size_original
        if size_delta > 0.5:
            return "drift", status_match

    return "match", status_match


async def replay_endpoint(
    flow: CapturedFlow,
    headers: dict[str, str] | None = None,
    cookies: list[tuple[str, str, str]] | None = None,
    timeout: float = 15.0,
    insecure: bool = False,
    impersonate: str = "chrome",
) -> ReplayResult:
    """Replay a single captured flow and return a categorized ReplayResult."""
    from curl_cffi.requests import AsyncSession

    req_headers: dict[str, str] = {}

    for k, v in flow.request_headers.items():
        if k.lower() not in _HOP_BY_HOP:
            req_headers[k.lower()] = v

    if headers:
        for k, v in headers.items():
            req_headers[k.lower()] = v

    start = time.monotonic()
    error: str | None = None
    replayed_status: int | None = None
    replayed_body = b""

    try:
        if cookies:
            cookie_str = cookies_for_host(cookies, _request_host(flow))
            if cookie_str:
                # Merge with any existing cookie header
                existing = req_headers.get("cookie", "")
                req_headers["cookie"] = (
                    existing + "; " + cookie_str if existing else cookie_str
                )

        async with AsyncSession(impersonate=impersonate) as session:
            resp = await session.request(
                method=flow.method,
                url=flow.url,
                headers=req_headers,
                data=flow.request_body or None,
                timeout=timeout,
                verify=not insecure,
                allow_redirects=True,
            )
            replayed_status = resp.status_code
            replayed_body = resp.content
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    elapsed_ms = round((time.monotonic() - start) * 1000, 1)

    size_original = len(flow.response_body)
    size_replayed = len(replayed_body)

    body_shape_match, body_shape_diff = compare_shape(
        flow.response_body, replayed_body
    )

    category, status_match = _assign_category(
        flow,
        replayed_status,
        body_shape_match,
        size_original,
        size_replayed,
        error,
    )

    return ReplayResult(
        original_flow=flow,
        replayed_status=replayed_status,
        elapsed_ms=elapsed_ms,
        error=error,
        category=category,
        status_match=status_match,
        body_shape_match=body_shape_match,
        body_shape_diff=body_shape_diff,
        size_original=size_original,
        size_replayed=size_replayed,
    )


def _filter_flows(
    flows: list[CapturedFlow],
    include_unsafe: bool,
) -> tuple[list[CapturedFlow], list[CapturedFlow]]:
    """Return (safe_or_all, unsafe). If include_unsafe, unsafe is empty."""
    if include_unsafe:
        return flows, []
    safe: list[CapturedFlow] = []
    unsafe: list[CapturedFlow] = []
    for f in flows:
        (safe if f.method.upper() in _SAFE_METHODS else unsafe).append(f)
    return safe, unsafe


def _deduplicate(flows: list[CapturedFlow]) -> list[CapturedFlow]:
    """Keep most recent flow per (method, dedup_key) group."""
    seen: dict[tuple[str, str], CapturedFlow] = {}
    for flow in flows:
        key = (flow.method.upper(), replay_dedup_key(flow.path))
        existing = seen.get(key)
        if existing is None or flow.timestamp > existing.timestamp:
            seen[key] = flow
    return list(seen.values())



async def _replay_with_retry(
    flow: CapturedFlow,
    headers: dict[str, str] | None,
    cookies: list[tuple[str, str, str]],
    timeout: float,
    insecure: bool,
    impersonate: str = "chrome",
) -> ReplayResult:
    backoff_delays = [1.0, 2.0, 4.0]
    for attempt, delay in enumerate([0.0] + backoff_delays):
        if delay:
            await asyncio.sleep(delay)
        result = await replay_endpoint(
            flow,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            insecure=insecure,
            impersonate=impersonate,
        )
        if result.replayed_status == 429 and attempt < len(backoff_delays):
            continue
        return result
    return result  # type: ignore[return-value]


async def run_replay(
    bundle_dir: str | None = None,
    domain: str | None = None,
    filter_: str | None = None,
    timeout: float = 15.0,
    cookie_file: str | None = None,
    extra_headers: dict[str, str] | None = None,
    include_unsafe: bool = False,
    insecure: bool = False,
    dry_run: bool = False,
    json_output: bool = False,
    output_file: str | None = None,
    impersonate: str = "chrome",
) -> list[ReplayResult]:
    """Replay captured endpoints serially, aborting on auth failure or block."""
    if bundle_dir:
        bundle = Path(bundle_dir)
    elif domain:
        bundle = find_latest_bundle(domain)
        if bundle is None:
            raise FileNotFoundError(
                f"No capture bundle found for domain: {domain}"
            )
    else:
        raise ValueError("Either bundle_dir or domain must be provided")

    flows_path = bundle / "flows.jsonl"
    if not flows_path.exists():
        raise FileNotFoundError(f"flows.jsonl not found in {bundle}")

    all_flows = read_capture_jsonl(str(flows_path))

    safe_flows, unsafe_flows = _filter_flows(all_flows, include_unsafe)

    if filter_:
        safe_flows = [
            f for f in safe_flows if fnmatch.fnmatch(f.path, filter_)
        ]

    flows = _deduplicate(safe_flows)

    if not domain:
        session_path = bundle / "session.json"
        with suppress(FileNotFoundError, json.JSONDecodeError, KeyError):
            domain = json.loads(session_path.read_text()).get("domain")
    resolved_domain = domain or "unknown"

    if dry_run:
        from rich.console import Console

        from apisniff.output import render_dry_run
        console = Console(stderr=True)
        render_dry_run(flows, unsafe_flows, resolved_domain, console)
        return []

    cookies: list[tuple[str, str, str]] = []
    if cookie_file:
        cookies = parse_cookie_file(cookie_file)

    results: list[ReplayResult] = []
    abort: ReplayAbort | None = None

    for flow in flows:
        result = await _replay_with_retry(
            flow, extra_headers, cookies, timeout, insecure, impersonate,
        )
        results.append(result)

        remaining = len(flows) - len(results)
        if result.category == "auth_expired":
            abort = ReplayAbort("auth expired", remaining)
            break
        if result.category == "blocked":
            abort = ReplayAbort("blocked", remaining)
            break
        if result.replayed_status == 429:
            abort = ReplayAbort("rate limited (retries exhausted)", remaining)
            break

    from rich.console import Console

    from apisniff.output import render_replay, replay_to_json

    if json_output:
        output = replay_to_json(results, resolved_domain, abort)
        if output_file:
            Path(output_file).write_text(output)
        else:
            sys.stdout.write(output + "\n")
    else:
        console = Console(stderr=True)
        render_replay(results, console, abort)
        if output_file:
            Path(output_file).write_text(
                replay_to_json(results, resolved_domain, abort)
            )

    return results

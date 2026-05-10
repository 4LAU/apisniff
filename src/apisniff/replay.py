from __future__ import annotations

import asyncio
import fnmatch
import json
import sys
import time
from pathlib import Path
from typing import Any, Literal

from apisniff.models import CapturedFlow, ReplayResult, replay_dedup_key
from apisniff.recon import _CAPTURES_DIR, read_capture_jsonl

_HOP_BY_HOP = frozenset(
    {"host", "content-length", "content-encoding", "transfer-encoding"}
)
_AUTH_HEADERS = frozenset(
    {"authorization", "cookie", "x-api-key", "api-key", "apikey"}
)
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_DEPTH = 3


# ---------------------------------------------------------------------------
# 7a. compare_shape()
# ---------------------------------------------------------------------------

def _shape(value: Any, depth: int) -> Any:
    """Return a structural shape descriptor for a JSON value."""
    if depth <= 0:
        return type(value).__name__
    if isinstance(value, dict):
        return {k: _shape(v, depth - 1) for k, v in value.items()}
    if isinstance(value, list):
        if not value:
            return []
        # Use first element's shape; check element type consistency
        first_shape = _shape(value[0], depth - 1)
        first_type = type(value[0]).__name__
        for item in value[1:]:
            if type(item).__name__ != first_type:
                # Mixed types — just report "mixed"
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

    # JSON↔non-JSON mismatch
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


# ---------------------------------------------------------------------------
# 7b. Cookie file parsing
# ---------------------------------------------------------------------------

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
            domain, _host_only, _path, _secure, _expiry, name, value = (
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
            )
            results.append((domain, name, value))
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
            suffix = domain[1:]  # strip leading dot
            if host == suffix or host.endswith("." + suffix):
                matching.append(f"{name}={value}")
        else:
            # Exact match
            if host == domain:
                matching.append(f"{name}={value}")
    return "; ".join(matching)


# ---------------------------------------------------------------------------
# 7c. replay_endpoint()
# ---------------------------------------------------------------------------

def _has_auth_headers(flow: CapturedFlow) -> bool:
    lower_keys = {k.lower() for k in flow.request_headers}
    return bool(lower_keys & _AUTH_HEADERS)


_ReplayCategory = Literal["match", "drift", "auth_expired", "blocked", "error"]


def _assign_category(
    flow: CapturedFlow,
    replayed_status: int | None,
    body_shape_match: bool,
    size_original: int,
    size_replayed: int,
    error: str | None,
) -> tuple[_ReplayCategory, bool]:
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

    # Status matches — check body shape and size
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
) -> ReplayResult:
    """Replay a single captured flow and return a categorized ReplayResult."""
    from curl_cffi.requests import AsyncSession

    # Build request headers
    req_headers: dict[str, str] = {}

    # Forward non-hop-by-hop headers from original flow
    for k, v in flow.request_headers.items():
        if k.lower() not in _HOP_BY_HOP:
            req_headers[k.lower()] = v

    # Apply cookie file cookies for this host
    if cookies:
        cookie_str = cookies_for_host(cookies, flow.host)
        if cookie_str:
            # Merge with any existing cookie header
            existing = req_headers.get("cookie", "")
            req_headers["cookie"] = (
                existing + "; " + cookie_str if existing else cookie_str
            )

    # Override with caller-supplied headers
    if headers:
        for k, v in headers.items():
            req_headers[k.lower()] = v

    start = time.monotonic()
    error: str | None = None
    replayed_status: int | None = None
    replayed_body = b""

    try:
        async with AsyncSession(impersonate="chrome") as session:
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


# ---------------------------------------------------------------------------
# 7d. run_replay()
# ---------------------------------------------------------------------------

def _find_latest_bundle(domain: str) -> Path | None:
    """Find the most recent bundle directory for a domain."""
    safe = domain.replace(".", "-").replace("/", "-")
    candidates = sorted(
        _CAPTURES_DIR.glob(f"{safe}_*"),
        key=lambda p: p.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _filter_flows(
    flows: list[CapturedFlow],
    include_unsafe: bool,
) -> tuple[list[CapturedFlow], list[CapturedFlow]]:
    """Return (safe_or_all, unsafe). If include_unsafe, unsafe is empty."""
    if include_unsafe:
        return flows, []
    safe = [f for f in flows if f.method.upper() in _SAFE_METHODS]
    unsafe = [f for f in flows if f.method.upper() not in _SAFE_METHODS]
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


async def run_replay(
    bundle_dir: str | None = None,
    domain: str | None = None,
    filter_: str | None = None,
    concurrency: int = 5,
    timeout: float = 15.0,
    cookie_file: str | None = None,
    extra_headers: dict[str, str] | None = None,
    include_unsafe: bool = False,
    insecure: bool = False,
    dry_run: bool = False,
    json_output: bool = False,
    output_file: str | None = None,
) -> list[ReplayResult]:
    """Orchestrate full replay of a captured session bundle."""
    # 1. Resolve bundle directory
    if bundle_dir:
        bundle = Path(bundle_dir)
    elif domain:
        bundle = _find_latest_bundle(domain)
        if bundle is None:
            raise FileNotFoundError(
                f"No capture bundle found for domain: {domain}"
            )
    else:
        raise ValueError("Either bundle_dir or domain must be provided")

    flows_path = bundle / "flows.jsonl"
    if not flows_path.exists():
        raise FileNotFoundError(f"flows.jsonl not found in {bundle}")

    # 2. Load flows
    all_flows = read_capture_jsonl(str(flows_path))

    # 3. Filter by method safety
    safe_flows, unsafe_flows = _filter_flows(all_flows, include_unsafe)

    # 4. Apply path filter
    if filter_:
        safe_flows = [
            f for f in safe_flows if fnmatch.fnmatch(f.path, filter_)
        ]

    # 5. Deduplicate
    flows = _deduplicate(safe_flows)

    # Derive domain from bundle name or flows
    resolved_domain = domain or bundle.name.rsplit("_", 1)[0].replace("-", ".")

    # 6. Dry run — return endpoint list
    if dry_run:
        from rich.console import Console

        from apisniff.output import render_dry_run
        console = Console(stderr=True)
        render_dry_run(flows, unsafe_flows, resolved_domain, console)
        return []

    # 6. Parse cookie file
    cookies: list[tuple[str, str, str]] = []
    if cookie_file:
        cookies = parse_cookie_file(cookie_file)

    # 7. Replay with semaphore, stagger, and 429 backoff
    semaphore = asyncio.Semaphore(concurrency)
    results: list[ReplayResult] = []

    async def _replay_with_retry(flow: CapturedFlow, index: int) -> ReplayResult:
        await asyncio.sleep(min(index * 0.1, 2.0))
        backoff_delays = [1.0, 2.0, 4.0]
        async with semaphore:
            for attempt, delay in enumerate([0.0] + backoff_delays):
                if delay:
                    await asyncio.sleep(delay)
                result = await replay_endpoint(
                    flow,
                    headers=extra_headers,
                    cookies=cookies,
                    timeout=timeout,
                    insecure=insecure,
                )
                if result.replayed_status == 429 and attempt < len(backoff_delays):
                    continue
                return result
        # Should never reach here, but satisfy type checker
        return result  # type: ignore[return-value]

    tasks = [_replay_with_retry(flow, i) for i, flow in enumerate(flows)]
    results = list(await asyncio.gather(*tasks))

    # 8. Output
    from rich.console import Console

    from apisniff.output import render_replay, replay_to_json

    if json_output:
        output = replay_to_json(results, resolved_domain)
        if output_file:
            Path(output_file).write_text(output)
        else:
            sys.stdout.write(output + "\n")
    else:
        console = Console(stderr=True)
        render_replay(results, console)
        if output_file:
            Path(output_file).write_text(
                replay_to_json(results, resolved_domain)
            )

    return results

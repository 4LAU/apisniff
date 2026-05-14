from __future__ import annotations

import asyncio
import json
import statistics
import time
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from apisniff.models import (
    ProbeAssessment,
    ProbeResult,
    ProbeVerdict,
    RateLimitResult,
    VendorMatch,
)
from apisniff.vendors import load_signatures, match_vendors

_TIMEOUT = 10.0
_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)
_BOT_UA = "python-httpx/0.27"
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/gql")
_GRAPHQL_INTROSPECTION = '{"query": "{__typename}"}'


async def _probe_httpx(
    url: str,
    label: str,
    ua: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> ProbeResult:
    req_headers = {"user-agent": ua}
    if headers:
        req_headers.update(headers)
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=_TIMEOUT,
            verify=False,
            proxy=proxy,
        ) as client:
            resp = await client.get(url, headers=req_headers)
            elapsed = (time.monotonic() - start) * 1000
            return ProbeResult(
                label=label,
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.content,
                elapsed_ms=round(elapsed, 1),
                error=None,
            )
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return ProbeResult(
            label=label,
            status=None,
            headers={},
            body=b"",
            elapsed_ms=round(elapsed, 1),
            error=f"{type(e).__name__}: {e}",
        )


async def _probe_curl_cffi(
    url: str,
    label: str,
    ua: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    impersonate: str = "chrome",
) -> ProbeResult:
    from curl_cffi.requests import AsyncSession

    req_headers = {"user-agent": ua}
    if headers:
        req_headers.update(headers)
    start = time.monotonic()
    try:
        async with AsyncSession() as session:
            resp = await session.get(
                url,
                headers=req_headers,
                impersonate=impersonate,
                timeout=_TIMEOUT,
                allow_redirects=True,
                verify=False,
                proxy=proxy,
            )
            elapsed = (time.monotonic() - start) * 1000
            return ProbeResult(
                label=label,
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.content,
                elapsed_ms=round(elapsed, 1),
                error=None,
            )
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return ProbeResult(
            label=label,
            status=None,
            headers={},
            body=b"",
            elapsed_ms=round(elapsed, 1),
            error=f"{type(e).__name__}: {e}",
        )


def classify_results(
    results: dict[str, ProbeResult],
    vendors: list[VendorMatch] | None = None,
) -> tuple[ProbeVerdict, str]:
    naked = results["naked"]
    impersonated = results["impersonated"]
    tls_only = results["tls_only"]

    all_blocked = naked.is_blocked and impersonated.is_blocked and tls_only.is_blocked
    all_pass = not naked.is_blocked and not impersonated.is_blocked and not tls_only.is_blocked

    any_challenge = naked.is_challenge or impersonated.is_challenge or tls_only.is_challenge
    all_challenge = naked.is_challenge and impersonated.is_challenge and tls_only.is_challenge

    vendor_prefix = ""
    if vendors:
        vendor_prefix = ", ".join(
            v.vendor.replace("_", " ").title() for v in vendors
        ) + " "

    def _rec(text: str) -> str:
        if vendor_prefix:
            return f"{vendor_prefix}{text}"
        return text[0].upper() + text[1:]

    if all_pass:
        if vendors:
            return (
                ProbeVerdict.NO_PROTECTION,
                _rec("detected but not enforcing on this page. "
                     "Raw HTTP requests sufficient, but API endpoints may "
                     "behave differently under bot detection."),
            )
        return (
            ProbeVerdict.NO_PROTECTION,
            "No active defenses detected. Raw HTTP requests sufficient.",
        )

    if all_challenge:
        if vendors:
            return ProbeVerdict.JS_CHALLENGE, _rec(
                "issuing JS challenges on all probe types. "
                "Full browser capture required. Use `apisniff recon`."
            )
        return ProbeVerdict.JS_CHALLENGE, (
            "All probes received JS challenges. "
            "Full browser capture required. Use `apisniff recon`."
        )

    if all_blocked:
        if vendors:
            return ProbeVerdict.FULL_BLOCK, _rec(
                "blocking all probe types. "
                "Full browser with manual interaction required. "
                "Use `apisniff recon`."
            )
        return ProbeVerdict.FULL_BLOCK, (
            "All probes blocked. "
            "Full browser with manual interaction required. "
            "Use `apisniff recon`."
        )

    if naked.is_blocked and not impersonated.is_blocked:
        if tls_only.is_blocked:
            return ProbeVerdict.CLIENT_DEPENDENT, _rec(
                "filtering on both TLS fingerprint and User-Agent. "
                "Requests must present a browser-like TLS handshake and realistic User-Agent."
            )
        return ProbeVerdict.CLIENT_DEPENDENT, _rec(
            "filtering on TLS fingerprint. "
            "Requests must present a browser-like TLS handshake (JA3/JA4)."
        )

    if not naked.is_blocked and impersonated.is_blocked:
        if tls_only.is_blocked:
            return ProbeVerdict.CLIENT_DEPENDENT, _rec(
                "detecting impersonated browser TLS fingerprints. "
                "The defense distinguishes real browsers from clients mimicking browser handshakes. "
                "Bot-identified clients pass because they bypass browser validation."
            )
        return ProbeVerdict.CLIENT_DEPENDENT, _rec(
            "blocking requests that present a browser User-Agent without "
            "completing JavaScript challenges. Bot-identified clients pass because they "
            "don't trigger the browser validation path. "
            "A full browser session is required for browser-level access."
        )

    if any_challenge and not all_challenge:
        return ProbeVerdict.CLIENT_DEPENDENT, _rec(
            "challenging selectively based on client signals. "
            "A browser-like TLS fingerprint and User-Agent may bypass challenges."
        )

    return ProbeVerdict.CLIENT_DEPENDENT, _rec(
        "producing mixed results across probe types. "
        "A browser-like TLS fingerprint is likely required."
    )


async def detect_graphql(
    base_url: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> tuple[list[str], bool]:
    found: list[str] = []
    introspection = False

    async def _check(path: str) -> None:
        nonlocal introspection
        url = base_url.rstrip("/") + path
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                verify=False,
                proxy=proxy,
            ) as client:
                resp = await client.post(
                    url,
                    content=_GRAPHQL_INTROSPECTION,
                    headers={
                        "content-type": "application/json",
                        "user-agent": _CHROME_UA,
                        **(headers or {}),
                    },
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data:
                            found.append(path)
                            if "__typename" in str(data.get("data", {})):
                                introspection = True
                    except Exception:
                        pass
        except Exception:
            pass

    await asyncio.gather(*[_check(p) for p in _GRAPHQL_PATHS])
    return found, introspection


_GRAPHQL_INTROSPECTION_FULL = json.dumps({
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args { ...InputValue }
        }
      }
    }

    fragment FullType on __Type {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { ...InputValue }
        type { ...TypeRef }
        isDeprecated deprecationReason
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { ...TypeRef }
    }

    fragment InputValue on __InputValue {
      name description type { ...TypeRef } defaultValue
    }

    fragment TypeRef on __Type {
      kind name
      ofType { kind name ofType { kind name ofType { kind name
        ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      } } }
    }
    """
})


async def fetch_graphql_schema(
    url: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> dict | None:
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, verify=False, proxy=proxy,
        ) as client:
            resp = await client.post(
                url,
                content=_GRAPHQL_INTROSPECTION_FULL,
                headers={
                    "content-type": "application/json",
                    "user-agent": _CHROME_UA,
                    **(headers or {}),
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    return data
    except Exception:
        pass
    return None


async def probe_rate_limit(
    url: str,
    count: int = 20,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    impersonate: str = "chrome",
) -> RateLimitResult:
    results: list[ProbeResult] = []
    first_block_at: int | None = None
    block_status: int | None = None
    retry_after: str | None = None

    for i in range(count):
        r = await _probe_curl_cffi(
            url, f"rate_{i}", _CHROME_UA,
            headers=headers, proxy=proxy, impersonate=impersonate,
        )
        results.append(r)
        if r.status in (429, 503) and first_block_at is None:
            first_block_at = i + 1
            block_status = r.status
            retry_after = r.headers.get("retry-after")
            break

    times = [r.elapsed_ms for r in results if r.status is not None]
    median_ms = statistics.median(times) if times else 0.0

    silent_throttle = False
    if len(times) >= 4:
        mid = len(times) // 2
        first_half_median = statistics.median(times[:mid])
        second_half_median = statistics.median(times[mid:])
        if first_half_median > 0 and second_half_median > 2 * first_half_median:
            silent_throttle = True

    return RateLimitResult(
        requests_sent=len(results),
        first_block_at=first_block_at,
        block_status=block_status,
        retry_after=retry_after,
        median_ms=round(median_ms, 1),
        silent_throttle=silent_throttle,
    )


async def run_probes(
    url: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    skip_graphql: bool = False,
    impersonate: str = "chrome",
    probe_rate: bool = False,
) -> ProbeAssessment:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    tasks = [
        _probe_httpx(url, "naked", _BOT_UA, headers, proxy),
        _probe_curl_cffi(url, "impersonated", _CHROME_UA, headers, proxy, impersonate=impersonate),
        _probe_curl_cffi(url, "tls_only", _BOT_UA, headers, proxy, impersonate=impersonate),
    ]
    if not skip_graphql:
        tasks.append(detect_graphql(url, headers, proxy))

    gathered = await asyncio.gather(*tasks)

    naked, impersonated, tls_only = gathered[0], gathered[1], gathered[2]
    results = {
        "naked": naked,
        "impersonated": impersonated,
        "tls_only": tls_only,
    }

    sigs = load_signatures()
    vendors = match_vendors(list(results.values()), sigs)

    verdict, recommendation = classify_results(results, vendors)

    graphql_endpoints: list[str] = []
    graphql_introspection = False
    graphql_schema_path: str | None = None
    if not skip_graphql:
        graphql_endpoints, graphql_introspection = gathered[3]
        if graphql_introspection and graphql_endpoints:
            schema_url = url.rstrip("/") + graphql_endpoints[0]
            schema = await fetch_graphql_schema(schema_url, headers, proxy)
            if schema:
                from apisniff.bundle import CAPTURES_DIR
                domain = urlparse(url).hostname or "unknown"
                ts = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M")
                schema_path = CAPTURES_DIR / f"{domain}-schema-{ts}.graphql.json"
                CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
                CAPTURES_DIR.chmod(0o700)
                schema_path.write_text(json.dumps(schema, indent=2))
                graphql_schema_path = str(schema_path)

    rate_limit: RateLimitResult | None = None
    if probe_rate:
        rate_limit = await probe_rate_limit(
            url, headers=headers, proxy=proxy, impersonate=impersonate,
        )

    return ProbeAssessment(
        url=url,
        verdict=verdict,
        recommendation=recommendation,
        results=results,
        vendors=vendors,
        graphql_endpoints=graphql_endpoints,
        graphql_introspection=graphql_introspection,
        graphql_schema_path=graphql_schema_path,
        rate_limit=rate_limit,
    )

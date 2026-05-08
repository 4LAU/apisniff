from __future__ import annotations

import asyncio
import json
import time

import httpx

from apisniff.models import (
    ProbeAssessment,
    ProbeResult,
    ProbeVerdict,
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
            error=str(e),
        )


async def _probe_curl_cffi(
    url: str,
    label: str,
    ua: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
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
                impersonate="chrome",
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
            error=str(e),
        )


def classify_results(
    results: dict[str, ProbeResult],
) -> tuple[ProbeVerdict, str]:
    naked = results["naked"]
    impersonated = results["impersonated"]
    tls_only = results["tls_only"]

    all_blocked = naked.is_blocked and impersonated.is_blocked and tls_only.is_blocked
    all_pass = not naked.is_blocked and not impersonated.is_blocked and not tls_only.is_blocked

    any_challenge = naked.is_challenge or impersonated.is_challenge or tls_only.is_challenge
    all_challenge = naked.is_challenge and impersonated.is_challenge and tls_only.is_challenge

    if all_pass:
        return (
            ProbeVerdict.NO_PROTECTION,
            "No active defenses detected. Raw HTTP requests sufficient.",
        )

    if all_challenge:
        return ProbeVerdict.JS_CHALLENGE, (
            "All probes received JS challenges. "
            "Full browser capture recommended — use `apisniff recon`."
        )

    if all_blocked:
        return ProbeVerdict.FULL_BLOCK, (
            "All probes blocked. "
            "Full browser with manual interaction recommended — use `apisniff recon`."
        )

    if naked.is_blocked and not impersonated.is_blocked:
        if tls_only.is_blocked:
            return ProbeVerdict.CLIENT_DEPENDENT, (
                "Impersonated client changed outcome; UA also matters. "
                "Use curl_cffi with Chrome profile and realistic User-Agent."
            )
        return ProbeVerdict.CLIENT_DEPENDENT, (
            "Impersonated client changed outcome; TLS likely a factor. "
            "Use curl_cffi with Chrome profile."
        )

    if any_challenge and not all_challenge:
        return ProbeVerdict.CLIENT_DEPENDENT, (
            "Some probes received challenges. "
            "Use curl_cffi with Chrome profile for best results."
        )

    return ProbeVerdict.CLIENT_DEPENDENT, (
        "Mixed results across probes. Use curl_cffi with Chrome profile."
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
                _raw = resp.json()
                data = await _raw if asyncio.iscoroutine(_raw) else _raw
                if "data" in data and "__schema" in data.get("data", {}):
                    return data
    except Exception:
        pass
    return None


async def run_probes(
    url: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    skip_graphql: bool = False,
) -> ProbeAssessment:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    tasks = [
        _probe_httpx(url, "naked", _BOT_UA, headers, proxy),
        _probe_curl_cffi(url, "impersonated", _CHROME_UA, headers, proxy),
        _probe_curl_cffi(url, "tls_only", _BOT_UA, headers, proxy),
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

    verdict, recommendation = classify_results(results)

    sigs = load_signatures()
    vendors = match_vendors(list(results.values()), sigs)

    graphql_endpoints: list[str] = []
    graphql_introspection = False
    if not skip_graphql:
        graphql_endpoints, graphql_introspection = gathered[3]

    return ProbeAssessment(
        url=url,
        verdict=verdict,
        recommendation=recommendation,
        results=results,
        vendors=vendors,
        graphql_endpoints=graphql_endpoints,
        graphql_introspection=graphql_introspection,
    )

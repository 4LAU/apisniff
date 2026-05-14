from __future__ import annotations

import json
import re
from pathlib import Path

from apisniff.models import CapturedFlow, ProbeResult, VendorMatch

_SIGNATURES_PATH = Path(__file__).parent / "signatures" / "vendors.json"

_COOKIE_ATTRS = frozenset({
    "expires", "max-age", "domain", "path", "samesite", "secure", "httponly",
})

_SPECIFIC_VENDORS = frozenset({"datadome", "perimeterx", "imperva", "akamai", "cloudflare"})


def load_signatures(path: Path | None = None) -> dict:
    p = path or _SIGNATURES_PATH
    with open(p) as f:
        sigs = json.load(f)
    for vendor_sigs in sigs.values():
        for level in ("high", "medium", "low"):
            for signal in vendor_sigs.get(level, []):
                if "pattern" in signal:
                    signal["_compiled"] = re.compile(signal["pattern"])
    return sigs


def _extract_cookies(headers: dict[str, str]) -> set[str]:
    names: set[str] = set()
    cookie_val = headers.get("cookie", "")
    if cookie_val:
        for part in cookie_val.split(";"):
            name = part.strip().split("=", 1)[0].strip().lower()
            if name:
                names.add(name)
    sc_val = headers.get("set-cookie", "")
    if sc_val:
        for part in sc_val.replace("\n", ", ").split(", "):
            part = part.strip()
            if not part or "=" not in part:
                continue
            candidate = part.split("=", 1)[0].strip().lower()
            if candidate in _COOKIE_ATTRS:
                continue
            if ";" in candidate:
                candidate = candidate.rsplit(";", 1)[-1].strip()
                if not candidate or candidate in _COOKIE_ATTRS:
                    continue
            if candidate:
                names.add(candidate)
    return names


class _PreparedResult:
    __slots__ = ("headers_lower", "cookies", "body_text", "status")

    def __init__(self, result: ProbeResult) -> None:
        self.headers_lower = {k.lower(): v for k, v in result.headers.items()}
        self.cookies = _extract_cookies(result.headers)
        self.body_text = (
            result.body[:100_000].decode("utf-8", errors="replace").lower()
            if result.body else ""
        )
        self.status = result.status


def _signal_matches(signal: dict, prep: _PreparedResult) -> bool:
    sig_type = signal["type"]

    if sig_type == "header_present":
        return signal["key"].lower() in prep.headers_lower

    if sig_type == "header_value":
        val = prep.headers_lower.get(signal["key"].lower(), "")
        return val.lower() == signal["value"].lower()

    if sig_type == "header_starts_with":
        val = prep.headers_lower.get(signal["key"].lower(), "")
        return val.lower().startswith(signal["value"].lower())

    if sig_type == "header_name_regex":
        compiled = signal["_compiled"]
        return any(compiled.match(k) for k in prep.headers_lower)

    if sig_type == "cookie_name":
        return signal["key"] in prep.cookies

    if sig_type == "cookie_name_regex":
        compiled = signal["_compiled"]
        return any(compiled.match(c) for c in prep.cookies)

    if sig_type == "cookie_name_startswith":
        return any(c.startswith(signal["prefix"]) for c in prep.cookies)

    if sig_type == "body_contains":
        return signal["value"].lower() in prep.body_text

    if sig_type == "status_code":
        return prep.status == signal["value"]

    return False


def _compute_confidence(high_count: int, medium_count: int, low_count: int) -> str | None:
    if high_count > 0:
        return "high"
    if medium_count >= 2:
        return "high"
    if medium_count == 1:
        return "medium"
    if low_count > 0:
        return "low"
    return None


def flows_to_probe_results(flows: list[CapturedFlow]) -> list[ProbeResult]:
    return [
        ProbeResult(
            label="captured", status=f.response_status,
            headers=f.response_headers, body=f.response_body,
            elapsed_ms=0.0, error=None,
        )
        for f in flows
    ]


def match_vendors(
    results: list[ProbeResult],
    signatures: dict,
) -> list[VendorMatch]:
    matched_specific: set[str] = set()
    matches: list[VendorMatch] = []
    preps = [_PreparedResult(r) for r in results]

    for vendor_name in sorted(signatures, key=lambda v: (v not in _SPECIFIC_VENDORS, v)):
        vendor_sigs = signatures[vendor_name]
        high_count = 0
        medium_count = 0
        low_count = 0
        matched_signals: list[str] = []

        for prep in preps:
            for level in ("high", "medium", "low"):
                for signal in vendor_sigs.get(level, []):
                    if _signal_matches(signal, prep):
                        detail = signal.get("key", signal.get("value", signal.get("pattern", "")))
                        sig_desc = f"{signal['type']}:{detail}"
                        if sig_desc not in matched_signals:
                            matched_signals.append(sig_desc)
                            if level == "high":
                                high_count += 1
                            elif level == "medium":
                                medium_count += 1
                            else:
                                low_count += 1

        confidence = _compute_confidence(high_count, medium_count, low_count)
        if confidence is None:
            continue

        if vendor_name in _SPECIFIC_VENDORS:
            matched_specific.add(vendor_name)

        overlaps = matched_specific & {"datadome", "akamai", "perimeterx"}
        if vendor_name == "shape_security" and overlaps:
            continue

        matches.append(VendorMatch(
            vendor=vendor_name,
            confidence=confidence,
            signals=matched_signals,
        ))

    return matches

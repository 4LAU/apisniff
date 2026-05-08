from __future__ import annotations

import json
import re
from pathlib import Path

from apisniff.models import ProbeResult, VendorMatch

_SIGNATURES_PATH = Path(__file__).parent.parent.parent / "signatures" / "vendors.json"

_SPECIFIC_VENDORS = frozenset({"datadome", "perimeterx", "imperva", "akamai", "cloudflare"})


def load_signatures(path: Path | None = None) -> dict:
    p = path or _SIGNATURES_PATH
    with open(p) as f:
        return json.load(f)


def _extract_cookies(headers: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for key in ("cookie", "set-cookie"):
        value = headers.get(key, "")
        if not value:
            continue
        for part in value.replace(",", ";").split(";"):
            name = part.strip().split("=", 1)[0].strip()
            if name:
                names.add(name)
    return names


def _signal_matches(signal: dict, result: ProbeResult) -> bool:
    sig_type = signal["type"]
    headers = result.headers

    if sig_type == "header_present":
        return signal["key"].lower() in {k.lower() for k in headers}

    if sig_type == "header_value":
        key = signal["key"].lower()
        expected = signal["value"].lower()
        for k, v in headers.items():
            if k.lower() == key and v.lower() == expected:
                return True
        return False

    if sig_type == "header_starts_with":
        key = signal["key"].lower()
        prefix = signal["value"].lower()
        for k, v in headers.items():
            if k.lower() == key and v.lower().startswith(prefix):
                return True
        return False

    if sig_type == "header_name_regex":
        pattern = re.compile(signal["pattern"])
        return any(pattern.match(k.lower()) for k in headers)

    if sig_type == "cookie_name":
        cookies = _extract_cookies(headers)
        return signal["key"] in cookies

    if sig_type == "cookie_name_regex":
        pattern = re.compile(signal["pattern"])
        cookies = _extract_cookies(headers)
        return any(pattern.match(c) for c in cookies)

    if sig_type == "cookie_name_startswith":
        prefix = signal["prefix"]
        cookies = _extract_cookies(headers)
        return any(c.startswith(prefix) for c in cookies)

    if sig_type == "body_contains":
        if not result.body:
            return False
        text = result.body[:100_000].decode("utf-8", errors="replace").lower()
        return signal["value"].lower() in text

    if sig_type == "status_code":
        return result.status == signal["value"]

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


def match_vendors(
    results: list[ProbeResult],
    signatures: dict,
) -> list[VendorMatch]:
    matched_specific: set[str] = set()
    matches: list[VendorMatch] = []

    for vendor_name in sorted(signatures, key=lambda v: (v not in _SPECIFIC_VENDORS, v)):
        vendor_sigs = signatures[vendor_name]
        high_count = 0
        medium_count = 0
        low_count = 0
        matched_signals: list[str] = []

        for result in results:
            for level in ("high", "medium", "low"):
                for signal in vendor_sigs.get(level, []):
                    if _signal_matches(signal, result):
                        sig_desc = f"{signal['type']}:{signal.get('key', signal.get('value', signal.get('pattern', '')))}"
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

        if vendor_name == "shape_security" and matched_specific & {"datadome", "akamai", "perimeterx"}:
            continue

        matches.append(VendorMatch(
            vendor=vendor_name,
            confidence=confidence,
            signals=matched_signals,
        ))

    return matches

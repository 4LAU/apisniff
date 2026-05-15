from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from apisniff.auth import detect_auth
from apisniff.classify import (
    Classifier,
    _request_content_type,
    classify_flow,
    is_api_like,
    target_host,
)
from apisniff.models import CapturedFlow, normalize_path
from apisniff.surface import (
    IMPORTANT_SURFACE_CATEGORIES,
    CaptureClassificationContext,
    SurfaceCategory,
    SurfaceClassification,
)

_OPENAPI_HOST_INCLUDE_CATEGORIES = frozenset({
    "business_api",
    "auth",
    "third_party_api",
    "unknown_api_like",
})
_SAFE_TAGS = frozenset({"allowlisted", "antibot_js"})


@dataclass(frozen=True, slots=True)
class OpenAPISelection:
    include_third_party: bool = False
    include_categories: frozenset[str] = frozenset()
    include_hosts: frozenset[str] = frozenset()


def build_capture_context(
    flows: list[CapturedFlow],
    domain: str,
) -> CaptureClassificationContext:
    classifier = Classifier(domain)
    for flow in flows:
        classifier.classify_surface(flow)
    return classifier.context()


def classify_flows(
    flows: list[CapturedFlow],
    domain: str,
    context: CaptureClassificationContext | None = None,
) -> list[SurfaceClassification]:
    context = context or build_capture_context(flows, domain)
    target = target_host(domain)
    return [classify_flow(flow, target, context) for flow in flows]


def derive_surface_records(
    flows: list[CapturedFlow],
    domain: str,
    context: CaptureClassificationContext | None = None,
) -> tuple[CaptureClassificationContext, list[dict]]:
    context = context or build_capture_context(flows, domain)
    classifications = classify_flows(flows, domain, context)
    ctx_dict = context.to_dict()
    records = [
        {
            "flow_index": index,
            "method": flow.method.upper(),
            "host": flow.host.lower().rstrip("."),
            "path": flow.path,
            "capture_context": ctx_dict,
            "classification": classification.to_dict(),
        }
        for index, (flow, classification) in enumerate(zip(flows, classifications, strict=True))
    ]
    return context, records


def is_api_flow(flow: CapturedFlow) -> bool:
    api_like, _, _ = is_api_like(flow)
    return api_like


def select_openapi_flow(
    flow: CapturedFlow,
    classification: SurfaceClassification,
    domain: str,
    selection: OpenAPISelection | None = None,
) -> bool:
    selection = selection or OpenAPISelection()
    host = flow.host.lower().rstrip(".")
    requested_host = target_host(domain)
    category = classification.category

    if category == "options":
        return False
    if host in selection.include_hosts:
        return classification.api_like and category in _OPENAPI_HOST_INCLUDE_CATEGORIES
    if category in selection.include_categories:
        return category not in {"static", "non_api", "options"}
    if selection.include_third_party and category == "third_party_api":
        return True
    return host == requested_host and category in {"business_api", "auth"}


def classify_spec_flow(flow: CapturedFlow, domain: str) -> tuple[bool, SurfaceCategory, str]:
    classification = classify_flow(flow, target_host(domain))
    include = select_openapi_flow(flow, classification, domain)
    return include, classification.category, classification.reason


def is_spec_flow(
    flow: CapturedFlow,
    domain: str,
    selection: OpenAPISelection | None = None,
) -> bool:
    classification = classify_flow(flow, target_host(domain))
    return select_openapi_flow(flow, classification, domain, selection)


def _auth_summary(group: list[CapturedFlow]) -> list[dict]:
    return [pattern.to_dict() for pattern in detect_auth(group)]


def _safe_inventory_tags(group: list[CapturedFlow]) -> list[str]:
    tags: set[str] = set()
    categories = set(SurfaceCategory.__args__)
    for flow in group:
        for tag in flow.tags:
            if (
                tag in _SAFE_TAGS
                or tag.startswith("surface:") and tag.removeprefix("surface:") in categories
            ):
                tags.add(tag)
    return sorted(tags)


def build_surface_inventory(
    flows: list[CapturedFlow],
    domain: str,
    classifications: list[SurfaceClassification] | None = None,
    selection: OpenAPISelection | None = None,
) -> list[dict]:
    """Return a safe endpoint inventory for meaningful captured surface traffic."""
    selection = selection or OpenAPISelection()
    classifications = classifications or classify_flows(flows, domain)
    groups: dict[
        tuple[str, str, str, str, bool],
        list[tuple[CapturedFlow, SurfaceClassification]],
    ] = defaultdict(list)

    for flow, classification in zip(flows, classifications, strict=True):
        if classification.category not in IMPORTANT_SURFACE_CATEGORIES:
            continue
        include = select_openapi_flow(flow, classification, domain, selection)
        key = (
            flow.method.upper(),
            flow.host.lower().rstrip("."),
            normalize_path(flow.path),
            classification.category,
            include,
        )
        groups[key].append((flow, classification))

    inventory: list[dict] = []
    for (method, host, normalized, category, include), items in sorted(groups.items()):
        group = [flow for flow, _ in items]
        first_classification = items[0][1]
        inventory.append({
            "method": method,
            "host": host,
            "path": normalized,
            "category": category,
            "reason": first_classification.reason,
            "host_role": first_classification.host_role,
            "count": len(group),
            "status_codes": sorted({f.response_status for f in group}),
            "request_content_types": sorted({
                ct for flow in group if (ct := _request_content_type(flow))
            }),
            "response_content_types": sorted({f.content_type for f in group if f.content_type}),
            "observed_auth": _auth_summary(group),
            "tags": _safe_inventory_tags(group),
            "included_in_openapi": include,
            "classifier_version": first_classification.classifier_version,
        })
    return inventory


def summarize_spec_selection(
    flows: list[CapturedFlow],
    domain: str,
    classifications: list[SurfaceClassification] | None = None,
    selection: OpenAPISelection | None = None,
) -> dict:
    """Summarize OpenAPI inclusion decisions by category."""
    selection = selection or OpenAPISelection()
    classifications = classifications or classify_flows(flows, domain)
    summary = {
        "total_flows": len(flows),
        "included": 0,
        "excluded": 0,
        "categories": {},
    }
    categories: dict[SurfaceCategory, dict[str, int]] = {}
    for flow, classification in zip(flows, classifications, strict=True):
        include = select_openapi_flow(flow, classification, domain, selection)
        bucket = categories.setdefault(classification.category, {"included": 0, "excluded": 0})
        if include:
            summary["included"] += 1
            bucket["included"] += 1
        else:
            summary["excluded"] += 1
            bucket["excluded"] += 1
    summary["categories"] = categories
    return summary

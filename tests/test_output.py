import json

from apisniff.output import probe_to_dict, probe_to_json
from apisniff.models import (
    ProbeAssessment,
    ProbeResult,
    ProbeVerdict,
    VendorMatch,
)


def _assessment() -> ProbeAssessment:
    return ProbeAssessment(
        url="https://example.com",
        verdict=ProbeVerdict.CLIENT_DEPENDENT,
        recommendation="Use curl_cffi with Chrome profile.",
        results={
            "naked": ProbeResult("naked", 403, {}, b"blocked", 150.0, None),
            "impersonated": ProbeResult("impersonated", 200, {}, b"ok", 90.0, None),
            "tls_only": ProbeResult("tls_only", 200, {}, b"ok", 95.0, None),
        },
        vendors=[VendorMatch("cloudflare", "high", ["header_present:cf-ray"])],
        graphql_endpoints=["/graphql"],
        graphql_introspection=True,
    )


def test_probe_to_dict():
    d = probe_to_dict(_assessment())
    assert d["url"] == "https://example.com"
    assert d["verdict"] == "client_dependent"
    assert d["recommendation"] == "Use curl_cffi with Chrome profile."
    assert len(d["vendors"]) == 1
    assert d["vendors"][0]["vendor"] == "cloudflare"
    assert d["probes"]["naked"]["status"] == 403
    assert d["probes"]["impersonated"]["status"] == 200
    assert d["graphql"]["endpoints"] == ["/graphql"]
    assert d["graphql"]["introspection"] is True


def test_probe_to_json():
    j = probe_to_json(_assessment())
    parsed = json.loads(j)
    assert parsed["verdict"] == "client_dependent"

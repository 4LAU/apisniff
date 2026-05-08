import pytest

from apisniff.models import ProbeResult
from apisniff.vendors import load_signatures, match_vendors


@pytest.fixture
def signatures():
    return load_signatures()


def _result(
    status=200,
    headers=None,
    body=b"",
    label="naked",
) -> ProbeResult:
    return ProbeResult(
        label=label,
        status=status,
        headers=headers or {},
        body=body,
        elapsed_ms=100.0,
        error=None,
    )


def test_load_signatures(signatures):
    assert "cloudflare" in signatures
    assert "datadome" in signatures
    assert len(signatures) == 25


def test_match_cloudflare_high(signatures):
    result = _result(headers={"cf-mitigated": "challenge"})
    matches = match_vendors([result], signatures)
    cf = next(m for m in matches if m.vendor == "cloudflare")
    assert cf.confidence == "high"


def test_match_cloudflare_medium(signatures):
    result = _result(headers={"cf-ray": "abc123"})
    matches = match_vendors([result], signatures)
    cf = next(m for m in matches if m.vendor == "cloudflare")
    assert cf.confidence == "medium"


def test_match_datadome_cookie(signatures):
    result = _result(headers={"cookie": "datadome=abc123; other=value"})
    matches = match_vendors([result], signatures)
    dd = next(m for m in matches if m.vendor == "datadome")
    assert dd.confidence == "high"


def test_match_akamai_body(signatures):
    result = _result(body=b"<script>var bmak.foo = 1;</script>")
    matches = match_vendors([result], signatures)
    ak = next(m for m in matches if m.vendor == "akamai")
    assert ak.confidence == "high"


def test_no_match(signatures):
    result = _result(headers={"server": "nginx"}, body=b"<html>hello</html>")
    matches = match_vendors([result], signatures)
    assert len(matches) == 0


def test_specificity_datadome_before_shape(signatures):
    """DataDome explicit header should not false-positive as Shape Security regex."""
    result = _result(headers={"x-datadome-cid": "abc"})
    matches = match_vendors([result], signatures)
    vendors = [m.vendor for m in matches]
    assert "datadome" in vendors
    assert "shape_security" not in vendors


def test_multiple_vendors(signatures):
    result = _result(
        headers={"cf-ray": "abc"},
        body=b"hcaptcha.com challenge",
    )
    matches = match_vendors([result], signatures)
    vendors = {m.vendor for m in matches}
    assert "cloudflare" in vendors
    assert "hcaptcha" in vendors


def test_linkedin_status_999(signatures):
    result = _result(status=999)
    matches = match_vendors([result], signatures)
    li = next(m for m in matches if m.vendor == "linkedin")
    assert li.confidence == "high"


def test_confidence_two_medium_is_high(signatures):
    """Two medium signals → high confidence."""
    result = _result(headers={
        "cookie": "_px2=abc; _px3=def",
        "x-px-authorization": "token",
    })
    matches = match_vendors([result], signatures)
    px = next(m for m in matches if m.vendor == "perimeterx")
    assert px.confidence == "high"


def test_set_cookie_attributes_not_in_names():
    """Set-Cookie attributes (Path, HttpOnly, Secure) must not appear as cookie names."""
    result = _result(headers={
        "set-cookie": "datadome=abc123; Path=/; HttpOnly; Secure",
    })
    from apisniff.vendors import _extract_cookies
    names = _extract_cookies(result.headers)
    assert "datadome" in names
    assert "path" not in names
    assert "httponly" not in names
    assert "secure" not in names


def test_multi_value_set_cookie():
    """Multiple Set-Cookie headers joined by newline should all be parsed."""
    result = _result(headers={
        "set-cookie": "a=1; Path=/\nb=2; HttpOnly\nc=3; Secure",
    })
    from apisniff.vendors import _extract_cookies
    names = _extract_cookies(result.headers)
    assert names == {"a", "b", "c"}

from apisniff.classify import Classifier
from apisniff.models import CapturedFlow


def _flow(
    host="example.com",
    path="/api/v1/users",
    method="GET",
    request_headers=None,
    response_status=200,
    response_headers=None,
    response_body=b'{"data": []}',
) -> CapturedFlow:
    return CapturedFlow(
        method=method,
        host=host,
        path=path,
        url=f"https://{host}{path}",
        request_headers=request_headers or {},
        request_body=b"",
        response_status=response_status,
        response_headers=response_headers or {"content-type": "application/json"},
        response_body=response_body,
    )


def test_api_flow_kept():
    """Without this test, a change could ship that drops valid API flows and nobody would know."""
    c = Classifier(target_domain="example.com")
    flow = _flow()
    result = c.classify(flow)
    assert result is not None
    assert "api_signal" in result.tags or len(result.tags) == 0


def test_noise_domain_dropped():
    """Without this test, a change could ship that keeps noise domain traffic and pollute results."""
    c = Classifier(target_domain="example.com")
    flow = _flow(host="google-analytics.com", path="/collect")
    result = c.classify(flow)
    assert result is None


def test_allowlist_domain_kept():
    """Without this test, a change could ship that drops antibot challenge flows silently."""
    c = Classifier(target_domain="example.com")
    flow = _flow(host="challenges.cloudflare.com", path="/cdn-cgi/challenge-platform/h/g/123")
    result = c.classify(flow)
    assert result is not None
    assert "allowlisted" in result.tags


def test_third_party_dropped():
    """Without this test, a change could ship that keeps unrelated third-party traffic silently."""
    c = Classifier(target_domain="example.com")
    flow = _flow(host="unrelated-cdn.net", path="/widget.js")
    result = c.classify(flow)
    assert result is None


def test_related_domain_via_referer():
    """Without this test, a change could ship that drops CDN flows tied to the target via Referer."""
    c = Classifier(target_domain="example.com")
    flow = _flow(
        host="api.example-cdn.net",
        request_headers={"referer": "https://example.com/page"},
    )
    result = c.classify(flow)
    assert result is not None


def test_static_asset_dropped():
    """Without this test, a change could ship that keeps plain JS assets and bloat recon output."""
    c = Classifier(target_domain="example.com")
    flow = _flow(
        path="/static/app.js",
        response_headers={"content-type": "application/javascript"},
        response_body=b"console.log('hello')",
    )
    result = c.classify(flow)
    assert result is None


def test_antibot_js_kept():
    """Without this test, a change could ship that drops antibot JS files containing 2+ markers."""
    c = Classifier(target_domain="example.com")
    body = b"var x = navigator.webdriver; bmak.init(); sensor_data = {};"
    flow = _flow(
        path="/static/security.js",
        response_headers={"content-type": "application/javascript"},
        response_body=body,
    )
    result = c.classify(flow)
    assert result is not None
    assert "antibot_js" in result.tags


def test_telemetry_path_dropped():
    """Without this test, a change could ship that keeps telemetry/beacon paths and skew analysis."""
    c = Classifier(target_domain="example.com")
    flow = _flow(path="/rum.gif")
    result = c.classify(flow)
    assert result is None


def test_options_dropped():
    """Without this test, a change could ship that keeps OPTIONS preflight requests silently."""
    c = Classifier(target_domain="example.com")
    flow = _flow(method="OPTIONS")
    result = c.classify(flow)
    assert result is None

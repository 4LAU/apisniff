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
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow())
    assert result.action == "keep"
    assert result.flow is not None


def test_noise_domain_dropped():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(host="google-analytics.com", path="/collect"))
    assert result.action == "drop"
    assert result.category == "noise_domain"


def test_allowlist_domain_kept():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(
        host="challenges.cloudflare.com",
        path="/cdn-cgi/challenge-platform/h/g/123",
    ))
    assert result.action == "keep"
    assert "allowlisted" in result.flow.tags


def test_third_party_dropped():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(host="unrelated-cdn.net", path="/widget.js"))
    assert result.action == "drop"
    assert result.category == "third_party"


def test_related_domain_via_referer():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(
        host="api.example-cdn.net",
        request_headers={"referer": "https://example.com/page"},
    ))
    assert result.action == "keep"


def test_static_asset_dropped():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(
        path="/static/app.js",
        response_headers={"content-type": "application/javascript"},
        response_body=b"console.log('hello')",
    ))
    assert result.action == "drop"
    assert result.category == "static_asset"


def test_antibot_js_kept():
    c = Classifier(target_domain="example.com")
    body = b"var x = navigator.webdriver; bmak.init(); sensor_data = {};"
    result = c.classify(_flow(
        path="/static/security.js",
        response_headers={"content-type": "application/javascript"},
        response_body=body,
    ))
    assert result.action == "keep"
    assert "antibot_js" in result.flow.tags


def test_telemetry_path_dropped():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(path="/rum.gif"))
    assert result.action == "drop"
    assert result.category == "path_telemetry"


def test_options_dropped():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(method="OPTIONS"))
    assert result.action == "drop"
    assert result.category == "options"


def test_co_uk_domain_extraction():
    c = Classifier(target_domain="shop.example.co.uk")
    result = c.classify(_flow(host="api.example.co.uk"))
    assert result.action == "keep"


def test_herokuapp_is_third_party():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(host="myapp.herokuapp.com"))
    assert result.action == "drop"


def test_ip_address_not_crash():
    c = Classifier(target_domain="example.com")
    result = c.classify(_flow(host="192.168.1.1"))
    assert result.action == "drop"

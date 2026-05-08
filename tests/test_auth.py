from apisniff.auth import ExtractedCookie, cookies_to_cookiejar, detect_auth, extract_cookies
from apisniff.models import CapturedFlow


def _flow(
    host="example.com",
    path="/api/v1/users",
    request_headers=None,
    response_headers=None,
    response_body=b"",
    timestamp=1.0,
) -> CapturedFlow:
    return CapturedFlow(
        method="GET",
        host=host,
        path=path,
        url=f"https://{host}{path}",
        request_headers=request_headers or {},
        request_body=b"",
        response_status=200,
        response_headers=response_headers or {},
        response_body=response_body,
        timestamp=timestamp,
    )


def test_detect_bearer():
    flows = [_flow(request_headers={"authorization": "Bearer eyJhbGc..."})]
    patterns = detect_auth(flows)
    assert any(p.auth_type == "bearer" for p in patterns)


def test_detect_basic_auth():
    flows = [_flow(request_headers={"authorization": "Basic dXNlcjpwYXNz"})]
    patterns = detect_auth(flows)
    assert any(p.auth_type == "basic" for p in patterns)


def test_detect_api_key_header():
    flows = [_flow(request_headers={"x-api-key": "abc123"})]
    patterns = detect_auth(flows)
    assert any(p.auth_type == "api_key_header" for p in patterns)


def test_detect_api_key_query():
    flows = [_flow(path="/api/data?api_key=abc123")]
    patterns = detect_auth(flows)
    assert any(p.auth_type == "api_key_query" for p in patterns)


def test_detect_session_cookie():
    flows = [_flow(request_headers={"cookie": "PHPSESSID=abc123; other=val"})]
    patterns = detect_auth(flows)
    assert any(p.auth_type == "session_cookie" and p.detail == "phpsessid" for p in patterns)


def test_detect_token_endpoint():
    flows = [_flow(path="/oauth/token")]
    patterns = detect_auth(flows)
    assert any(p.auth_type == "token_endpoint" for p in patterns)


def test_detect_auth_dedup_and_count():
    flows = [
        _flow(request_headers={"authorization": "Bearer token1"}),
        _flow(request_headers={"authorization": "Bearer token2"}),
        _flow(request_headers={"x-api-key": "key1"}),
    ]
    patterns = detect_auth(flows)
    bearer = next(p for p in patterns if p.auth_type == "bearer")
    assert bearer.flow_count == 2
    assert patterns[0].flow_count >= patterns[-1].flow_count


def test_detect_auth_no_auth():
    flows = [_flow()]
    patterns = detect_auth(flows)
    assert patterns == []


def test_extract_cookies_from_request():
    flows = [_flow(
        request_headers={"cookie": "session=abc; theme=dark"},
    )]
    cookies = extract_cookies(flows)
    names = {c.name for c in cookies}
    assert "session" in names
    assert "theme" in names
    assert all(c.source == "request" for c in cookies)


def test_extract_cookies_from_response_set_cookie():
    flows = [_flow(
        response_headers={"set-cookie": "tracker=xyz; Path=/; Secure; HttpOnly"},
    )]
    cookies = extract_cookies(flows)
    assert len(cookies) == 1
    c = cookies[0]
    assert c.name == "tracker"
    assert c.value == "xyz"
    assert c.path == "/"
    assert c.secure is True
    assert c.source == "response"


def test_extract_cookies_domain_from_set_cookie_attr():
    flows = [_flow(
        host="www.example.com",
        response_headers={"set-cookie": "id=1; Domain=.example.com; Path=/app"},
    )]
    cookies = extract_cookies(flows)
    c = cookies[0]
    assert c.domain == "example.com"
    assert c.host_only is False
    assert c.path == "/app"


def test_extract_cookies_host_only_when_no_domain():
    flows = [_flow(
        host="api.example.com",
        response_headers={"set-cookie": "sid=abc"},
    )]
    cookies = extract_cookies(flows)
    c = cookies[0]
    assert c.domain == "api.example.com"
    assert c.host_only is True


def test_extract_cookies_dedup_by_name_domain_path():
    flows = [
        _flow(
            response_headers={"set-cookie": "id=old; Path=/"},
            timestamp=1.0,
        ),
        _flow(
            response_headers={"set-cookie": "id=new; Path=/"},
            timestamp=2.0,
        ),
    ]
    cookies = extract_cookies(flows)
    assert len(cookies) == 1
    assert cookies[0].value == "new"


def test_extract_cookies_multi_set_cookie():
    flows = [_flow(
        response_headers={"set-cookie": "a=1; Path=/\nb=2; Secure"},
    )]
    cookies = extract_cookies(flows)
    names = {c.name for c in cookies}
    assert names == {"a", "b"}


def test_cookies_to_cookiejar_format():
    cookies = [
        ExtractedCookie(name="sid", value="abc", domain="example.com",
                        host_only=False, path="/", secure=True, source="response"),
        ExtractedCookie(name="lang", value="en", domain="api.example.com",
                        host_only=True, path="/", secure=False, source="request"),
    ]
    output = cookies_to_cookiejar(cookies)
    lines = output.strip().split("\n")
    # Only response-derived cookies are exported (request cookies have invented scope)
    assert len(lines) == 1
    parts0 = lines[0].split("\t")
    assert parts0[0] == ".example.com"
    assert parts0[1] == "TRUE"
    assert parts0[3] == "TRUE"
    assert parts0[5] == "sid"


def test_cookies_to_cookiejar_skips_request_only():
    cookies = [
        ExtractedCookie(name="theme", value="dark", domain="example.com",
                        host_only=True, path="/", secure=False, source="request"),
    ]
    output = cookies_to_cookiejar(cookies)
    assert output.strip() == ""

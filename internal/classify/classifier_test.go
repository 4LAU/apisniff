package classify

import (
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func testFlow(overrides func(*model.CapturedFlow)) model.CapturedFlow {
	flow := model.CapturedFlow{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/v1/users",
		URL:             "https://example.com/api/v1/users",
		RequestHeaders:  map[string]string{},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    []byte(`{"data":[]}`),
		BodyEncoding:    "base64",
		Tags:            []string{},
	}
	if overrides != nil {
		overrides(&flow)
	}
	return flow
}

func TestAPIFlowKept(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(nil))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}
	if result.Category != model.BusinessAPI {
		t.Fatalf("category = %q", result.Category)
	}
}

func TestAuthPathKeptAsAuthCategory(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Path = "/oauth/token"
		f.URL = "https://example.com/oauth/token"
		f.Method = "POST"
	}))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}
	if result.Category != model.Auth {
		t.Fatalf("category = %q, want %q", result.Category, model.Auth)
	}
}

func TestKeptNonAPILikeFlowUsesUnknownAPILikeCategory(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Path = "/dashboard"
		f.URL = "https://example.com/dashboard"
		f.ResponseHeaders = map[string]string{"content-type": "text/plain"}
		f.ResponseBody = []byte("not an api response")
	}))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}
	if result.APILike {
		t.Fatalf("APILike = true, want false")
	}
	if result.Category != model.UnknownAPILike {
		t.Fatalf("category = %q, want %q", result.Category, model.UnknownAPILike)
	}
}

func TestCaptureTagsPreserved(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Tags = []string{"websocket", "response_body_bytes:128"}
	}))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}
	for _, tag := range []string{"websocket", "response_body_bytes:128"} {
		if !hasTag(kept.Tags, tag) {
			t.Fatalf("missing tag %q in %+v", tag, kept.Tags)
		}
	}
}

func TestNoiseDomainDropped(t *testing.T) {
	result, _ := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "google-analytics.com"
		f.Path = "/collect"
	}))
	if result.Action != "drop" || result.Reason != "noise_domain" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAllowlistDomainKept(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "challenges.cloudflare.com"
		f.Path = "/cdn-cgi/challenge-platform/h/g/123"
	}))
	if result.Action != "keep" || kept == nil || !hasTag(kept.Tags, "allowlisted") {
		t.Fatalf("result = %+v kept=%+v", result, kept)
	}
}

func TestThirdPartyDropped(t *testing.T) {
	result, _ := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "unrelated-cdn.net"
		f.Path = "/widget.js"
	}))
	if result.Action != "drop" || result.Reason != "third_party" {
		t.Fatalf("result = %+v", result)
	}
}

func TestRelatedDomainViaReferer(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "api.example-cdn.net"
		f.RequestHeaders = map[string]string{"referer": "https://example.com/page"}
	}))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}
}

func TestRelatedDomainLearnedFromCSP(t *testing.T) {
	classifier := Must("example.com")
	first, firstKept := classifier.Classify(testFlow(func(f *model.CapturedFlow) {
		f.ResponseHeaders = map[string]string{
			"content-type":            "application/json",
			"content-security-policy": "connect-src 'self' https://api.example-cdn.net https://google-analytics.com",
		}
	}))
	if first.Action != "keep" || firstKept == nil {
		t.Fatalf("first result = %+v kept=%v", first, firstKept)
	}

	result, kept := classifier.Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "api.example-cdn.net"
		f.URL = "https://api.example-cdn.net/api/v1/users"
	}))
	if result.Action != "keep" || kept == nil || result.HostRole != "same_site" {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}

	noiseResult, _ := classifier.Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "google-analytics.com"
		f.Path = "/api/v1/collect"
		f.URL = "https://google-analytics.com/api/v1/collect"
	}))
	if noiseResult.Action != "drop" || noiseResult.Reason != "noise_domain" {
		t.Fatalf("noise CSP domain should not be learned as related: %+v", noiseResult)
	}
}

func TestStaticAssetDropped(t *testing.T) {
	result, _ := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Path = "/static/app.js"
		f.ResponseHeaders = map[string]string{"content-type": "application/javascript"}
		f.ResponseBody = []byte("console.log('hello')")
	}))
	if result.Action != "drop" || result.Reason != "static_asset" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAllowlistBypassesTelemetryAndStaticDrops(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "challenges.cloudflare.com"
		f.Path = "/rum.gif"
		f.URL = "https://challenges.cloudflare.com/rum.gif"
		f.ResponseHeaders = map[string]string{"content-type": "application/javascript"}
		f.ResponseBody = []byte("console.log('challenge telemetry')")
	}))
	if result.Action != "keep" || kept == nil || !hasTag(kept.Tags, "allowlisted") {
		t.Fatalf("result = %+v kept=%+v", result, kept)
	}
	if result.Category != model.Antibot {
		t.Fatalf("category = %q, want %q", result.Category, model.Antibot)
	}
}

func TestAntibotJSKept(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Path = "/static/security.js"
		f.ResponseHeaders = map[string]string{"content-type": "application/javascript"}
		f.ResponseBody = []byte("var x = navigator.webdriver; bmak.init(); sensor_data = {};")
	}))
	if result.Action != "keep" || kept == nil || !hasTag(kept.Tags, "antibot_js") {
		t.Fatalf("result = %+v kept=%+v", result, kept)
	}
}

func TestSensorDataRequestDroppedAsAntibot(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Method = "POST"
		f.Path = "/api/v1/events"
		f.RequestBody = []byte(`{"sensor_data":{"ua":"webdriver"}}`)
	}))
	if kept != nil || result.Action != "drop" || result.Category != model.Antibot || !hasTag(result.Signals, "sensor_data") {
		t.Fatalf("result = %+v kept=%+v", result, kept)
	}
}

func TestTelemetrySubdomainDropped(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "analytics.example.com"
		f.URL = "https://analytics.example.com/api/v1/events"
		f.Path = "/api/v1/events"
	}))
	if kept != nil || result.Action != "drop" || result.Category != model.Telemetry || !hasTag(result.Signals, "telemetry_subdomain") {
		t.Fatalf("result = %+v kept=%+v", result, kept)
	}
}

func TestTelemetryPathDropped(t *testing.T) {
	result, _ := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Path = "/rum.gif"
	}))
	if result.Action != "drop" || result.Reason != "path_telemetry" {
		t.Fatalf("result = %+v", result)
	}
}

func TestOptionsDropped(t *testing.T) {
	result, _ := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Method = "OPTIONS"
	}))
	if result.Action != "drop" || result.Category != model.Options {
		t.Fatalf("result = %+v", result)
	}
}

func TestDomainExtraction(t *testing.T) {
	if got := ExtractRegisteredDomain("shop.example.co.uk"); got != "example.co.uk" {
		t.Fatalf("co.uk rd = %q", got)
	}
	if got := ExtractRegisteredDomain("myapp.herokuapp.com"); got != "myapp.herokuapp.com" {
		t.Fatalf("private rd = %q", got)
	}
}

func TestQueryStringBeaconNotDropped(t *testing.T) {
	result, _ := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Path = "/api/search?q=beacon.gif"
	}))
	if result.Action != "keep" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAuthPathUsesSegmentBoundariesAcrossRepeatedMatches(t *testing.T) {
	if isAuthPath("/authors") {
		t.Fatalf("authors should not be an auth path")
	}
	if isAuthPath("/loginButton") {
		t.Fatalf("loginButton should not be an auth path")
	}
	if !isAuthPath("/loginButton/login") {
		t.Fatalf("later login segment was not detected")
	}
}

func TestLocalhostPortIsSameSite(t *testing.T) {
	result, kept := Must("127.0.0.1:8765").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "127.0.0.1"
		f.Path = "/json-small"
	}))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}
}

func TestHTMLFetchIsAPILikeViaSecFetchDest(t *testing.T) {
	result, kept := Must("example.com").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Path = "/bin/rewards-catalog/list"
		f.URL = "https://example.com/bin/rewards-catalog/list"
		f.ResponseHeaders = map[string]string{"content-type": "text/html"}
		f.ResponseBody = []byte("<li class=tile></li>")
		f.RequestHeaders = map[string]string{
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
		}
	}))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
	}
	if !result.APILike {
		t.Fatalf("APILike = false, want true for an HTML fetch")
	}
	if result.Category != model.BusinessAPI {
		t.Fatalf("category = %q, want %q", result.Category, model.BusinessAPI)
	}
}

func TestHTMLFetchIsAPILikeViaXRequestedWith(t *testing.T) {
	if !isAPILike(testFlow(func(f *model.CapturedFlow) {
		f.ResponseHeaders = map[string]string{"content-type": "text/html"}
		f.Path = "/legacy/fragment"
		f.RequestHeaders = map[string]string{"x-requested-with": "XMLHttpRequest"}
	})) {
		t.Fatal("isAPILike = false, want true for XHR-flagged HTML fetch")
	}
}

func TestHTMLDocumentNavigationIsNotAPILike(t *testing.T) {
	if isAPILike(testFlow(func(f *model.CapturedFlow) {
		f.ResponseHeaders = map[string]string{"content-type": "text/html"}
		f.Path = "/articles/some-page"
		f.RequestHeaders = map[string]string{
			"sec-fetch-dest": "document",
			"sec-fetch-mode": "navigate",
		}
	})) {
		t.Fatal("isAPILike = true, want false for a top-level document navigation")
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

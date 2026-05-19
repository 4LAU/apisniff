package classify

import (
	"testing"

	"github.com/4LAU/apisniff-go/internal/model"
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

func TestLocalhostPortIsSameSite(t *testing.T) {
	result, kept := Must("127.0.0.1:8765").Classify(testFlow(func(f *model.CapturedFlow) {
		f.Host = "127.0.0.1"
		f.Path = "/json-small"
	}))
	if result.Action != "keep" || kept == nil {
		t.Fatalf("result = %+v kept=%v", result, kept)
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

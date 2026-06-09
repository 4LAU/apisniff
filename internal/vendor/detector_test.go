package vendor

import (
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func newTestDetector(t *testing.T) *Detector {
	t.Helper()
	detector, err := NewDetector()
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return detector
}

func TestDetectorMatchesEveryBundledVendorSignature(t *testing.T) {
	detector := newTestDetector(t)
	tests := []struct {
		name       string
		headers    map[string]string
		body       []byte
		status     int
		wantVendor string
		wantConf   string
	}{
		{name: "cloudflare", headers: map[string]string{"cf-mitigated": "challenge"}, status: 200, wantVendor: "cloudflare", wantConf: "high"},
		{name: "akamai", headers: map[string]string{"set-cookie": "_abck=abc; Path=/"}, status: 200, wantVendor: "akamai", wantConf: "high"},
		{name: "datadome", headers: map[string]string{"x-datadome-cid": "abc"}, status: 200, wantVendor: "datadome", wantConf: "high"},
		{name: "perimeterx", body: []byte("window._pxAppId = 'PX123'"), status: 200, wantVendor: "perimeterx", wantConf: "high"},
		{name: "imperva", body: []byte("Incapsula incident ID"), status: 200, wantVendor: "imperva", wantConf: "high"},
		{name: "kasada", headers: map[string]string{"x-kasada": "challenge"}, status: 200, wantVendor: "kasada", wantConf: "high"},
		{name: "shape_security", headers: map[string]string{"x-12345678-a": "1"}, status: 200, wantVendor: "shape_security", wantConf: "high"},
		{name: "aws_waf", headers: map[string]string{"x-amzn-waf-action": "captcha"}, status: 200, wantVendor: "aws_waf", wantConf: "high"},
		{name: "recaptcha", body: []byte("https://www.google.com/recaptcha/api.js"), status: 200, wantVendor: "recaptcha", wantConf: "high"},
		{name: "hcaptcha", body: []byte("https://js.hcaptcha.com/1/api.js"), status: 200, wantVendor: "hcaptcha", wantConf: "high"},
		{name: "cloudflare_turnstile", body: []byte("https://challenges.cloudflare.com/turnstile/v0/api.js"), status: 200, wantVendor: "cloudflare_turnstile", wantConf: "high"},
		{name: "f5_bigip", headers: map[string]string{"set-cookie": "BIGipServerpool=123; Path=/"}, status: 200, wantVendor: "f5_bigip", wantConf: "medium"},
		{name: "vercel", headers: map[string]string{"x-vercel-mitigated": "challenge"}, status: 200, wantVendor: "vercel", wantConf: "high"},
		{name: "reblaze", headers: map[string]string{"set-cookie": "rbzid=abc; Path=/"}, status: 200, wantVendor: "reblaze", wantConf: "medium"},
		{name: "cheq", body: []byte("CheqSdk.init()"), status: 200, wantVendor: "cheq", wantConf: "medium"},
		{name: "sucuri", body: []byte("Access denied by Sucuri"), status: 200, wantVendor: "sucuri", wantConf: "medium"},
		{name: "arkose_labs", body: []byte("https://client-api.arkoselabs.com/fc/api/"), status: 200, wantVendor: "arkose_labs", wantConf: "high"},
		{name: "geetest", body: []byte("https://static.geetest.com/static/js/gt.js"), status: 200, wantVendor: "geetest", wantConf: "high"},
		{name: "anubis", body: []byte(`<script id="anubis_challenge"></script>`), status: 200, wantVendor: "anubis", wantConf: "high"},
		{name: "threatmetrix", body: []byte("ThreatMetrix profiling enabled"), status: 200, wantVendor: "threatmetrix", wantConf: "medium"},
		{name: "meetrics", body: []byte("window.meetricsGlobal = {}"), status: 200, wantVendor: "meetrics", wantConf: "medium"},
		{name: "ocule", body: []byte("https://proxy.ocule.co.uk/script.js"), status: 200, wantVendor: "ocule", wantConf: "medium"},
		{name: "amazon_cloudfront", headers: map[string]string{"x-cache": "Error from cloudfront"}, status: 200, wantVendor: "amazon_cloudfront", wantConf: "medium"},
		{name: "linkedin", status: 999, wantVendor: "linkedin", wantConf: "high"},
		{name: "reddit", body: []byte("blocked by network security"), status: 200, wantVendor: "reddit", wantConf: "medium"},
	}
	if len(tests) != len(detector.signatures) {
		t.Fatalf("vendor test cases = %d, bundled signatures = %d", len(tests), len(detector.signatures))
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, ok := findVendorMatch(detector.Match(tt.headers, tt.body, tt.status), tt.wantVendor)
			if !ok {
				t.Fatalf("missing vendor %q", tt.wantVendor)
			}
			if match.Confidence != tt.wantConf {
				t.Fatalf("confidence = %q, want %q: %+v", match.Confidence, tt.wantConf, match)
			}
		})
	}
}

func TestDetectorDoesNotMatchPlainNginxResponse(t *testing.T) {
	matches := newTestDetector(t).Match(map[string]string{"server": "nginx"}, []byte("<html>hello</html>"), 200)
	if len(matches) != 0 {
		t.Fatalf("matches = %+v, want none", matches)
	}
}

func findVendorMatch(matches []model.VendorMatch, vendor string) (model.VendorMatch, bool) {
	for _, match := range matches {
		if match.Vendor == vendor {
			return match, true
		}
	}
	return model.VendorMatch{}, false
}

func TestSetCookieParsingDoesNotTreatAttributesAsCookieNames(t *testing.T) {
	names := cookieNames(map[string]string{
		"set-cookie": "sid=abc; Path=/; Secure; Partitioned\ncsrf=xyz; SameSite=None",
	})
	for _, want := range []string{"sid", "csrf"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing cookie %q in %#v", want, names)
		}
	}
	for _, unwanted := range []string{"path", "secure", "partitioned", "samesite"} {
		if _, ok := names[unwanted]; ok {
			t.Fatalf("cookie attribute %q treated as cookie name: %#v", unwanted, names)
		}
	}
}

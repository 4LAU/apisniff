package auth

import (
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func authFlow(update func(*model.CapturedFlow)) model.CapturedFlow {
	flow := model.CapturedFlow{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/v1/users",
		URL:             "https://example.com/api/v1/users",
		RequestHeaders:  map[string]string{},
		ResponseHeaders: map[string]string{},
		Timestamp:       1,
	}
	if update != nil {
		update(&flow)
	}
	return flow
}

func TestDetectAuthPatterns(t *testing.T) {
	flows := []model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"authorization": "Bearer token"} }),
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"authorization": "Bearer token2"} }),
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"x-api-key": "abc"} }),
		authFlow(func(f *model.CapturedFlow) { f.Path = "/oauth/token" }),
		authFlow(func(f *model.CapturedFlow) { f.Path = "/api/data?api_key=abc" }),
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"cookie": "PHPSESSID=abc; other=1"} }),
	}
	patterns := Detect(flows)
	if len(patterns) < 5 {
		t.Fatalf("patterns = %+v", patterns)
	}
	if patterns[0].AuthType != "bearer" || patterns[0].FlowCount != 2 {
		t.Fatalf("first pattern = %+v", patterns[0])
	}
}

func TestExtractCookiesAndCookiejar(t *testing.T) {
	cookies := ExtractCookies([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) {
			f.Timestamp = 1
			f.ResponseHeaders = map[string]string{"set-cookie": "id=old; Path=/"}
		}),
		authFlow(func(f *model.CapturedFlow) {
			f.Timestamp = 2
			f.ResponseHeaders = map[string]string{"set-cookie": "id=new; Domain=.example.com; Path=/; Secure\nb=2; Secure"}
		}),
		authFlow(func(f *model.CapturedFlow) {
			f.Timestamp = 3
			f.RequestHeaders = map[string]string{"cookie": "session=abc; theme=dark"}
		}),
	})
	if len(cookies) != 4 {
		t.Fatalf("cookies = %+v", cookies)
	}
	jar := CookiesToCookiejar(cookies)
	if !strings.Contains(jar, ".example.com\tTRUE\t/\tTRUE\t0\tid\tnew") {
		t.Fatalf("cookiejar = %q", jar)
	}
	if strings.Contains(jar, "session") {
		t.Fatalf("request cookie leaked into jar: %q", jar)
	}
}

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

func TestDetectBearer(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) {
			f.RequestHeaders = map[string]string{"authorization": "Bearer eyJhbGc..."}
		}),
	})
	if !hasPattern(patterns, "bearer", "authorization: bearer", 1) {
		t.Fatalf("patterns = %+v", patterns)
	}
}

func TestDetectBasicAuth(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) {
			f.RequestHeaders = map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}
		}),
	})
	if !hasPattern(patterns, "basic", "authorization: basic", 1) {
		t.Fatalf("patterns = %+v", patterns)
	}
}

func TestDetectAPIKeyHeader(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"X-API-Key": "abc123"} }),
	})
	if !hasPattern(patterns, "api_key_header", "x-api-key", 1) {
		t.Fatalf("patterns = %+v", patterns)
	}
}

func TestDetectAPIKeyQuery(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) { f.Path = "/api/data?api_key=abc123" }),
	})
	if !hasPattern(patterns, "api_key_query", "api_key", 1) {
		t.Fatalf("patterns = %+v", patterns)
	}
}

func TestDetectSessionCookie(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) {
			f.RequestHeaders = map[string]string{"cookie": "PHPSESSID=abc123; other=val"}
		}),
	})
	if !hasPattern(patterns, "session_cookie", "phpsessid", 1) {
		t.Fatalf("patterns = %+v", patterns)
	}
}

func TestDetectOAuthTokenEndpoint(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) { f.Path = "/oauth/token/" }),
	})
	if !hasPattern(patterns, "token_endpoint", "/oauth/token", 1) {
		t.Fatalf("patterns = %+v", patterns)
	}
}

func TestDetectMultipleAuthDedupAndCount(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"authorization": "Bearer token1"} }),
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"authorization": "Bearer token2"} }),
		authFlow(func(f *model.CapturedFlow) { f.RequestHeaders = map[string]string{"x-api-key": "key1"} }),
	})
	if !hasPattern(patterns, "bearer", "authorization: bearer", 2) {
		t.Fatalf("patterns = %+v", patterns)
	}
	if patterns[0].FlowCount < patterns[len(patterns)-1].FlowCount {
		t.Fatalf("patterns are not sorted by descending count: %+v", patterns)
	}
}

func TestDetectAuthNoAuth(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{authFlow(nil)})
	if len(patterns) != 0 {
		t.Fatalf("patterns = %+v, want none", patterns)
	}
}

func TestDetectAuthEdgeCasesDoNotFalsePositive(t *testing.T) {
	patterns := Detect([]model.CapturedFlow{
		authFlow(func(f *model.CapturedFlow) {
			f.Path = "/api/data?monkey=abc"
			f.RequestHeaders = map[string]string{
				"authorization": "Token abc",
				"cookie":        "theme=dark; nonsession=abc",
			}
		}),
	})
	if len(patterns) != 0 {
		t.Fatalf("patterns = %+v, want none", patterns)
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

func hasPattern(patterns []Pattern, authType, detail string, flowCount int) bool {
	for _, pattern := range patterns {
		if pattern.AuthType == authType && pattern.Detail == detail && pattern.FlowCount == flowCount {
			return true
		}
	}
	return false
}

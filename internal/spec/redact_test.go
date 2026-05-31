package spec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func redactionFlow(responseBody string) model.CapturedFlow {
	return model.CapturedFlow{
		Method:          "POST",
		Host:            "example.com",
		Path:            "/api/register",
		URL:             "https://example.com/api/register",
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     []byte(`{"email":"user@example.com"}`),
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    []byte(responseBody),
		BodyEncoding:    "base64",
		Tags:            []string{"category:business_api"},
	}
}

func TestSpecExamplesRedactCredentialPatterns(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{redactionFlow(`{
		"authorization": "Bearer sk_live_secret",
		"basic_auth": "Basic dXNlcjpzZWNyZXQ=",
		"stripe_publishable": "pk_test_123",
		"jwt": "eyJhbGciOiJSUzI1NiJ9.payload",
		"aws_secret": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"refresh_token": "rt_live_refresh",
		"name": "Ada"
	}`)}, "example.com", nil, Options{IncludeExamples: true})

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, pattern := range []string{"Bearer ", "sk_live_", "Basic ", "pk_test_", "eyJ", "wJalrXUtn", "rt_live_"} {
		if strings.Contains(out, pattern) {
			t.Fatalf("secret pattern %q leaked into spec:\n%s", pattern, out)
		}
	}
	if !strings.Contains(out, `"name"`) || !strings.Contains(out, `"Ada"`) {
		t.Fatalf("non-sensitive example was unexpectedly removed:\n%s", out)
	}
}

func TestSensitiveFieldNamesAlwaysRedactedInExamples(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{redactionFlow(`{
		"password": "plain-value",
		"credential": "plain-value",
		"api_key": "plain-value",
		"refresh_token": "plain-value",
		"client_secret": "plain-value",
		"safe_name": "plain-value"
	}`)}, "example.com", nil, Options{IncludeExamples: true})

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var redactedCount int
	walkExamples(t, doc, func(field string, example any) {
		switch field {
		case "password", "credential", "api_key", "refresh_token", "client_secret":
			redactedCount++
			if example != "***REDACTED***" {
				t.Fatalf("%s example = %#v, want redacted", field, example)
			}
		case "safe_name":
			if example != "plain-value" {
				t.Fatalf("safe_name example = %#v, want original", example)
			}
		}
	})
	if redactedCount != 5 {
		t.Fatalf("redacted sensitive field examples = %d, want 5\n%s", redactedCount, data)
	}
}

func walkExamples(t *testing.T, value any, visit func(field string, example any)) {
	t.Helper()
	var walk func(field string, value any)
	walk = func(field string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			if example, ok := typed["example"]; ok && field != "" {
				visit(field, example)
			}
			for key, child := range typed {
				nextField := field
				if key == "properties" {
					if props, ok := child.(map[string]any); ok {
						for propName, propSchema := range props {
							walk(propName, propSchema)
						}
						continue
					}
				}
				walk(nextField, child)
			}
		case []any:
			for _, child := range typed {
				walk(field, child)
			}
		}
	}
	walk("", value)
}

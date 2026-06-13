package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCapturedFlowContentType(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "strips charset parameter",
			headers: map[string]string{"content-type": "application/json; charset=utf-8"},
			want:    "application/json",
		},
		{
			name:    "header key lookup is case insensitive",
			headers: map[string]string{"Content-Type": "Text/HTML; charset=utf-8"},
			want:    "text/html",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := CapturedFlow{ResponseHeaders: tt.headers}
			if got := flow.ContentType(); got != tt.want {
				t.Fatalf("ContentType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCapturedFlowJSONLBase64Bodies(t *testing.T) {
	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	flow := CapturedFlow{
		Method:          "POST",
		Host:            "api.example.com",
		Path:            "/v1/users/123?expand=true",
		URL:             "https://api.example.com/v1/users/123?expand=true",
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     binary,
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"Content-Type": "application/json; charset=utf-8"},
		ResponseBody:    binary,
		Tags:            []string{"api"},
		Timestamp:       1710000000,
	}
	data, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["_body_encoding"] != "base64" {
		t.Fatalf("_body_encoding = %v, want base64", raw["_body_encoding"])
	}
	var decoded CapturedFlow
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.RequestBody, flow.RequestBody) {
		t.Fatalf("request body = %q, want %q", decoded.RequestBody, flow.RequestBody)
	}
	if !reflect.DeepEqual(decoded.ResponseBody, flow.ResponseBody) {
		t.Fatalf("response body = %q, want %q", decoded.ResponseBody, flow.ResponseBody)
	}
	if decoded.ContentType() != "application/json" {
		t.Fatalf("content type = %q", decoded.ContentType())
	}
}

func TestCapturedFlowLegacyBodySerializationNoMarker(t *testing.T) {
	data := []byte(`{
		"method": "GET",
		"host": "example.com",
		"path": "/legacy",
		"url": "https://example.com/legacy",
		"request_headers": {},
		"request_body": "hello legacy",
		"response_status": 200,
		"response_headers": {},
		"response_body": "{\"ok\": true}",
		"tags": [],
		"timestamp": 0
	}`)
	var flow CapturedFlow
	if err := json.Unmarshal(data, &flow); err != nil {
		t.Fatal(err)
	}
	if string(flow.RequestBody) != "hello legacy" {
		t.Fatalf("request body = %q", flow.RequestBody)
	}
	if string(flow.ResponseBody) != `{"ok": true}` {
		t.Fatalf("response body = %q", flow.ResponseBody)
	}
}

func TestCapturedFlowUnknownEncodingTreatedAsPlainText(t *testing.T) {
	data := []byte(`{
		"method": "GET",
		"host": "example.com",
		"path": "/unknown-enc",
		"url": "https://example.com/unknown-enc",
		"request_headers": {},
		"response_status": 200,
		"response_headers": {},
		"response_body": "plain text body",
		"_body_encoding": "gzip",
		"tags": [],
		"timestamp": 0
	}`)
	var flow CapturedFlow
	if err := json.Unmarshal(data, &flow); err != nil {
		t.Fatal(err)
	}
	if string(flow.ResponseBody) != "plain text body" {
		t.Fatalf("response body = %q, want plain text fallback", flow.ResponseBody)
	}
}

func TestNormalizePathCases(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/{userId}"},
		{"/api/users/12345", "/api/users/{userId}"},
		{"/api/objects/deadbeefcafe0000", "/api/objects/{objectId}"},
		{"/api/users/42?foo=bar", "/api/users/{userId}"},
		{"/orgs/99/repos/abc-def-ghi", "/orgs/{orgId}/repos/abc-def-ghi"},
		{"/v1/users/123/orders/550e8400-e29b-41d4-a716-446655440000", "/v1/users/{userId}/orders/{orderId}"},
		{"/creditcards/cc_9BMqukMwYVs6SY1psJlh0f", "/creditcards/{creditcardId}"},
		{"/virtualcards/vc_8fDYMNuzL6H7qNKajeMCCc", "/virtualcards/{virtualcardId}"},
		{"/organizations/org_AYPx4TzpatN9Bm3xW9VQUf/departments", "/organizations/{organizationId}/departments"},
		{"/users/u_3fsKhZHvqRFAo7XXNOz4Lv", "/users/{userId}"},
		{"/customers/cus_Nv8dManqwatb3rUp9Xy2", "/customers/{customerId}"},
		{"/events/01ARZ3NDEKTSV4RRFFQ69G5FAV", "/events/{eventId}"},
		{"/config/payment_processors", "/config/payment_processors"},
		{"/organizations/org_AYPx4TzpatN9Bm3xW9VQUf/receiptmanagementenabled", "/organizations/{organizationId}/receiptmanagementenabled"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := NormalizePath(tt.path); got != tt.want {
				t.Fatalf("NormalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestReplayDedupKeyCases(t *testing.T) {
	key1 := ReplayDedupKey("/search?q=apple&page=1")
	key2 := ReplayDedupKey("/search?q=banana&page=99")
	if key1 != key2 {
		t.Fatalf("same query parameter names produced different keys: %q != %q", key1, key2)
	}

	key3 := ReplayDedupKey("/search?q=apple")
	key4 := ReplayDedupKey("/search?query=apple")
	if key3 == key4 {
		t.Fatalf("different query parameter names produced same key: %q", key3)
	}

	if got := ReplayDedupKey("/v1/users/123?b=2&a=1&a=3"); got != "/v1/users/{userId}?a={v}&b={v}" {
		t.Fatalf("ReplayDedupKey = %q", got)
	}

	// Opaque IDs collapse to one replay key regardless of the concrete id.
	if a, b := ReplayDedupKey("/creditcards/cc_9BMqukMwYVs6SY1psJlh0f"),
		ReplayDedupKey("/creditcards/cc_7w7CLKmd9I77HX2fjHfGPB"); a != b {
		t.Fatalf("distinct cc_ ids produced different keys: %q != %q", a, b)
	}
	if a, b := ReplayDedupKey("/events/01ARZ3NDEKTSV4RRFFQ69G5FAV"),
		ReplayDedupKey("/events/01BX5ZZKBKACTAV9WEVGEMMVRZ"); a != b {
		t.Fatalf("distinct ULIDs produced different keys: %q != %q", a, b)
	}
	// Distinct static sibling routes must NOT share a key.
	if a, b := ReplayDedupKey("/users/search"),
		ReplayDedupKey("/users/notifications"); a == b {
		t.Fatalf("distinct static routes collapsed to same key: %q", a)
	}
}

func TestIsDynamicSegmentOpaqueIDs(t *testing.T) {
	dynamic := []string{
		"cc_9BMqukMwYVs6SY1psJlh0f",  // Extend credit card id (prefixed, mixed+digit)
		"vc_8fDYMNuzL6H7qNKajeMCCc",  // Extend virtual card id
		"org_AYPx4TzpatN9Bm3xW9VQUf", // Extend organization id
		"u_3fsKhZHvqRFAo7XXNOz4Lv",   // Extend user id (1-char prefix)
		"ii_7kubwtySFr65WYBNmu75BO",  // Extend issuer id
		"cus_Nv8dManqDmAa9XyZ12bC",   // Stripe-style prefix (vendor-neutral)
		"01ARZ3NDEKTSV4RRFFQ69G5FAV", // bare ULID (uppercase+digit, no prefix)
		"V1StGXR8Z5jdHi6Bxxxxxx9",    // bare nanoid-style token (mixed+digit)
	}
	for _, part := range dynamic {
		if !IsDynamicSegment(part) {
			t.Errorf("IsDynamicSegment(%q) = false, want true", part)
		}
	}

	static := []string{
		"payment_processors",        // prefix ok, tail <12 chars
		"event_acknowledgements",    // prefix ok, tail >=12 but all-lowercase, no digit -> readable
		"internal_configuration",    // prefix ok, readable lowercase tail
		"org_MemberRoles",           // allowlisted-looking prefix, CamelCase but tail <12 -> readable
		"receiptmanagementenabled",  // 24 chars, no digit -> long route word, not a token
		"sixmonthspendbycurrency",   // 23 chars, no digit -> long route word
		"outofpocketexpenses",       // 19 chars, no digit
		"creditcardsv2",             // no underscore, <20, has digit but short
		"Sign_Up",                   // uppercase prefix fails the lowercase-prefix shape gate
		"tok_visa",                  // tail too short
	}
	for _, part := range static {
		if IsDynamicSegment(part) {
			t.Errorf("IsDynamicSegment(%q) = true, want false", part)
		}
	}
}

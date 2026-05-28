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
}

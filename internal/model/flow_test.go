package model

import (
	"encoding/json"
	"testing"
)

func TestCapturedFlowJSONLBase64Bodies(t *testing.T) {
	flow := CapturedFlow{
		Method:          "POST",
		Host:            "api.example.com",
		Path:            "/v1/users/123?expand=true",
		URL:             "https://api.example.com/v1/users/123?expand=true",
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     []byte(`{"name":"a"}`),
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"Content-Type": "application/json; charset=utf-8"},
		ResponseBody:    []byte(`{"ok":true}`),
		Tags:            []string{"api"},
		Timestamp:       1710000000,
	}
	data, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CapturedFlow
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.RequestBody) != string(flow.RequestBody) {
		t.Fatalf("request body = %q, want %q", decoded.RequestBody, flow.RequestBody)
	}
	if string(decoded.ResponseBody) != string(flow.ResponseBody) {
		t.Fatalf("response body = %q, want %q", decoded.ResponseBody, flow.ResponseBody)
	}
	if decoded.ContentType() != "application/json" {
		t.Fatalf("content type = %q", decoded.ContentType())
	}
}

func TestNormalizeAndReplayDedupKey(t *testing.T) {
	if got := NormalizePath("/v1/users/123/orders/550e8400-e29b-41d4-a716-446655440000"); got != "/v1/users/{id}/orders/{id}" {
		t.Fatalf("NormalizePath = %q", got)
	}
	if got := ReplayDedupKey("/v1/users/123?b=2&a=1&a=3"); got != "/v1/users/{id}?a={v}&b={v}" {
		t.Fatalf("ReplayDedupKey = %q", got)
	}
}

package adapter

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestHARConversion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.har")
	body := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\n"))
	har := `{"log":{"entries":[
		{"startedDateTime":"2024-03-15T10:30:00Z","request":{"method":"POST","url":"https://api.example.com/v1/items?q=1","headers":[{"name":"Authorization","value":"Bearer token123"}],"postData":{"text":"{\"name\":\"widget\"}"}},"response":{"status":201,"headers":[{"name":"Content-Type","value":"application/json"},{"name":"Set-Cookie","value":"a=1"},{"name":"Set-Cookie","value":"b=2"}],"content":{"text":"{\"id\":42}"}}},
		{"request":{"method":"GET","url":"https://api.example.com/v1/image","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"` + body + `","encoding":"base64"}}}
	]}}`
	if err := os.WriteFile(path, []byte(har), 0o600); err != nil {
		t.Fatal(err)
	}
	flows, err := LoadHAR(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("flows = %d", len(flows))
	}
	first := flows[0]
	if first.Method != "POST" || first.Path != "/v1/items?q=1" || first.ResponseStatus != 201 {
		t.Fatalf("first = %+v", first)
	}
	if first.RequestHeaders["authorization"] != "Bearer token123" {
		t.Fatalf("headers = %+v", first.RequestHeaders)
	}
	if first.ResponseHeaders["set-cookie"] != "a=1\nb=2" {
		t.Fatalf("set-cookie = %q", first.ResponseHeaders["set-cookie"])
	}
	if string(first.RequestBody) != `{"name":"widget"}` || string(first.ResponseBody) != `{"id":42}` {
		t.Fatalf("bodies = %q %q", first.RequestBody, first.ResponseBody)
	}
	if string(flows[1].ResponseBody) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("base64 body = %q", flows[1].ResponseBody)
	}
}

func TestHARSkipsEntriesWithoutAbsoluteURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.har")
	har := `{"log":{"entries":[
		{"request":{"method":"GET","url":"/relative","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"bad"}}},
		{"request":{"method":"GET","url":"https://api.example.com/ok","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"ok"}}}
	]}}`
	if err := os.WriteFile(path, []byte(har), 0o600); err != nil {
		t.Fatal(err)
	}
	flows, err := LoadHAR(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || flows[0].URL != "https://api.example.com/ok" {
		t.Fatalf("flows = %#v", flows)
	}
}

func TestDetectFormats(t *testing.T) {
	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	jsonlPath := filepath.Join(dir, "flows.jsonl")
	burpPath := filepath.Join(dir, "burp.xml")
	os.WriteFile(harPath, []byte(`{"log":{"entries":[]}}`), 0o600)
	os.WriteFile(jsonlPath, []byte(`{"method":"GET"}`+"\n"), 0o600)
	os.WriteFile(burpPath, []byte(`<?xml version="1.0"?><items></items>`), 0o600)
	for path, want := range map[string]string{harPath: "har", jsonlPath: "jsonl", burpPath: "burp"} {
		got, err := Detect(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s detect = %q", path, got)
		}
	}
}

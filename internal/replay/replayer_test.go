package replay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/4LAU/apisniff-go/internal/model"
)

func replayFlow(method, rawURL, path string, status int, body []byte) model.CapturedFlow {
	return model.CapturedFlow{
		Method:          method,
		Host:            "example.com",
		Path:            path,
		URL:             rawURL,
		RequestHeaders:  map[string]string{"Connection": "keep-alive", "X-Trace": "1"},
		ResponseStatus:  status,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    body,
		BodyEncoding:    "base64",
		Timestamp:       1,
	}
}

func TestFilterFlowsExcludesUnsafeByDefault(t *testing.T) {
	flows := []model.CapturedFlow{
		replayFlow("GET", "https://example.com/a", "/a", 200, nil),
		replayFlow("POST", "https://example.com/b", "/b", 200, nil),
		replayFlow("OPTIONS", "https://example.com/c", "/c", 204, nil),
	}
	safe, unsafe := FilterFlows(flows, false)
	if len(safe) != 2 || len(unsafe) != 1 {
		t.Fatalf("safe=%d unsafe=%d", len(safe), len(unsafe))
	}
	all, unsafe := FilterFlows(flows, true)
	if len(all) != 3 || unsafe != nil {
		t.Fatalf("include unsafe all=%d unsafe=%v", len(all), unsafe)
	}
}

func TestBuildRequestRemovesHopByHopAndAddsCookies(t *testing.T) {
	flow := replayFlow("GET", "https://api.example.com/v1/users?q=1", "/v1/users?q=1", 200, nil)
	flow.Host = "api.example.com:443"
	req, err := buildRequest(context.Background(), flow, map[string]string{"Authorization": "Bearer x"}, []Cookie{{Domain: ".example.com", Name: "sid", Value: "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.RawQuery != "q=1" {
		t.Fatalf("query not preserved: %s", req.URL.String())
	}
	if req.Header.Get("connection") != "" {
		t.Fatalf("connection header was not stripped")
	}
	if req.Header.Get("authorization") != "Bearer x" {
		t.Fatalf("authorization header = %q", req.Header.Get("authorization"))
	}
	if req.Header.Get("cookie") != "sid=abc" {
		t.Fatalf("cookie header = %q", req.Header.Get("cookie"))
	}
}

func TestRunDryRunSummarizesSafeAndUnsafe(t *testing.T) {
	dir := t.TempDir()
	flowsPath := filepath.Join(dir, "flows.jsonl")
	writeFlows(t, flowsPath, []model.CapturedFlow{
		replayFlow("GET", "https://example.com/api/users", "/api/users", 200, []byte(`{"ok":true}`)),
		replayFlow("POST", "https://example.com/api/users", "/api/users", 201, []byte(`{"ok":true}`)),
	})

	summary, err := Run(context.Background(), Options{BundleOrDomain: flowsPath, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Mode != "dry_run" || summary.Summary["safe"] != 1 || summary.Summary["unsafe"] != 1 || summary.Summary["total"] != 2 {
		t.Fatalf("summary = %#v", summary)
	}
	if strings.Join(summary.Endpoints, ",") != "GET /api/users,POST /api/users" {
		t.Fatalf("endpoints = %#v", summary.Endpoints)
	}
}

func TestGoldenDryRunFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "golden", "phase5", "replay", "flows.jsonl")
	expectedPath := filepath.Join("..", "..", "testdata", "golden", "phase5", "replay", "expected-dry-run.json")
	summary, err := Run(context.Background(), Options{BundleOrDomain: path, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	summary.Domain = ""
	var expected Summary
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(summary, expected) {
		t.Fatalf("summary = %#v, want %#v", summary, expected)
	}
}

func writeFlows(t *testing.T, path string, flows []model.CapturedFlow) {
	t.Helper()
	var lines []string
	for _, flow := range flows {
		line, err := flow.ToJSONL()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

package finalize

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func TestFinalizeWritesSpecAndCatalog(t *testing.T) {
	dir := t.TempDir()
	flows := []model.CapturedFlow{
		{Method: "POST", Host: "api.x.com", Path: "/graphql", URL: "https://api.x.com/graphql",
			RequestHeaders: map[string]string{"content-type": "application/json"},
			RequestBody:    []byte(`{"operationName":"A","query":"query A{a}","variables":{"x":1}}`),
			ResponseStatus: 200, ResponseBody: []byte(`{"data":{"a":1}}`)},
	}
	sum, err := FinalizeBundle(dir, flows, "api.x.com")
	if err != nil {
		t.Fatal(err)
	}
	if sum.OperationCount != 1 {
		t.Fatalf("ops %d", sum.OperationCount)
	}
	for _, n := range []string{"openapi-spec.yaml", "graphql-operations.json"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("missing %s: %v", n, err)
		}
	}
}

func TestFromBundleMissingFlowsWarnsAndIsNonFatal(t *testing.T) {
	var warn bytes.Buffer
	flowsPath := filepath.Join(t.TempDir(), "nope.jsonl")
	sum := FromBundle(&warn, t.TempDir(), flowsPath, "x.com")
	if sum != (Summary{}) {
		t.Fatalf("expected empty Summary on missing flows, got %+v", sum)
	}
	got := warn.String()
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, flowsPath) {
		t.Fatalf("expected warning naming %s, got %q", flowsPath, got)
	}
}

func TestFromBundleFinalizeFailureWarnsAndIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	flow := model.CapturedFlow{Method: "POST", Host: "api.x.com", Path: "/graphql",
		URL:            "https://api.x.com/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"A","query":"query A{a}","variables":{"x":1}}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{"a":1}}`)}
	line, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	flowsPath := filepath.Join(dir, "flows.jsonl")
	if err := os.WriteFile(flowsPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file as bundleDir makes the spec write fail (ENOTDIR).
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var warn bytes.Buffer
	sum := FromBundle(&warn, notADir, flowsPath, "api.x.com")
	if sum != (Summary{}) {
		t.Fatalf("expected empty Summary on finalize failure, got %+v", sum)
	}
	got := warn.String()
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, notADir) {
		t.Fatalf("expected warning naming %s, got %q", notADir, got)
	}
}

func TestFromBundleNilWriterDoesNotPanic(t *testing.T) {
	sum := FromBundle(nil, t.TempDir(), filepath.Join(t.TempDir(), "nope.jsonl"), "x.com")
	if sum != (Summary{}) {
		t.Fatalf("expected empty Summary, got %+v", sum)
	}
}

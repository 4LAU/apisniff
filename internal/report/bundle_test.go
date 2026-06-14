package report

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/model"
)

func TestWriteBundleWritesSessionFlowsAndReport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	flows := []model.CapturedFlow{{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/users/123",
		URL:             "https://example.com/api/users/123",
		RequestHeaders:  map[string]string{"Cookie": "sid=secret"},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		Tags:            []string{"category:business_api"},
	}}
	session := model.SessionStats{
		Domain:     "example.com",
		TotalFlows: 1,
		KeptFlows:  1,
		Dropped:    map[string]int{},
	}

	if _, err := WriteBundle(dir, flows, session); err != nil {
		t.Fatal(err)
	}
	assertMode(t, dir, 0o700)
	for _, name := range []string{"session.json", "flows.jsonl", "report.md"} {
		assertMode(t, filepath.Join(dir, name), 0o600)
	}

	loaded, err := adapter.LoadJSONL(filepath.Join(dir, "flows.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Path != "/api/users/123" {
		t.Fatalf("loaded flows = %#v", loaded)
	}

	sessionData, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotSession model.SessionStats
	if err := json.Unmarshal(sessionData, &gotSession); err != nil {
		t.Fatal(err)
	}
	if gotSession.Domain != "example.com" || gotSession.KeptFlows != 1 {
		t.Fatalf("session = %#v", gotSession)
	}

	reportData, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	reportText := string(reportData)
	if !strings.Contains(reportText, "# API Sniff Report: example.com") {
		t.Fatalf("report missing title: %s", reportText)
	}
	if strings.Contains(reportText, "sid=secret") {
		t.Fatalf("report leaked cookie value: %s", reportText)
	}
}

func TestFetchGraphQLSchemasDetectsPathAndWritesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "query was not stripped: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method: "+r.Method, http.StatusMethodNotAllowed)
			return
		}
		if !strings.Contains(r.Header.Get("content-type"), "application/json") {
			http.Error(w, "unexpected content-type: "+r.Header.Get("content-type"), http.StatusUnsupportedMediaType)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer server.Close()

	flows := []model.CapturedFlow{{
		Method:          "POST",
		Host:            "example.test",
		Path:            "/graphql?operation=Viewer",
		URL:             server.URL + "/graphql?operation=Viewer",
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		ResponseHeaders: map[string]string{"content-type": "application/json"},
	}}

	results, err := FetchGraphQLSchemas(context.Background(), flows)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %#v", results)
	}
	if results[0].Endpoint != server.URL+"/graphql" {
		t.Fatalf("endpoint = %s", results[0].Endpoint)
	}
	if !results[0].Introspection || results[0].Status != http.StatusOK || results[0].Error != "" {
		t.Fatalf("result = %#v", results[0])
	}

	dir := t.TempDir()
	if err := WriteGraphQLResults(dir, results); err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Join(dir, "graphql.json"), 0o600)
	data, err := os.ReadFile(filepath.Join(dir, "graphql.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Endpoints     []string `json:"endpoints"`
		Introspection bool     `json:"introspection"`
		Results       []struct {
			Endpoint      string          `json:"endpoint"`
			Introspection bool            `json:"introspection"`
			Schema        json.RawMessage `json:"schema"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Endpoints) != 1 || payload.Endpoints[0] != server.URL+"/graphql" {
		t.Fatalf("endpoints = %#v", payload.Endpoints)
	}
	if !payload.Introspection || len(payload.Results) != 1 || len(payload.Results[0].Schema) == 0 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestFetchGraphQLSchemasDetectsGraphQLContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("content-type", "application/graphql-response+json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer server.Close()

	flows := []model.CapturedFlow{{
		Method:          "POST",
		Path:            "/api",
		URL:             server.URL + "/api",
		RequestHeaders:  map[string]string{"content-type": "application/graphql+json"},
		ResponseHeaders: map[string]string{"content-type": "application/json"},
	}}

	results, err := FetchGraphQLSchemas(context.Background(), flows)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Endpoint != server.URL+"/api" || !results[0].Introspection {
		t.Fatalf("results = %#v", results)
	}
}

func TestFetchGraphQLSchemasDetectsJSONQueryBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer server.Close()

	flows := []model.CapturedFlow{{
		Method:          "POST",
		Path:            "/api",
		URL:             server.URL + "/api",
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     []byte(`{"query":"query Viewer { viewer { id } }"}`),
		ResponseHeaders: map[string]string{"content-type": "application/json"},
	}}

	results, err := FetchGraphQLSchemas(context.Background(), flows)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Endpoint != server.URL+"/api" || !results[0].Introspection {
		t.Fatalf("results = %#v", results)
	}
}

func TestFetchGraphQLSchemasRecordsEndpointFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no introspection", http.StatusForbidden)
	}))
	defer server.Close()

	results, err := FetchGraphQLSchemas(context.Background(), []model.CapturedFlow{{
		Path:            "/graphql",
		URL:             server.URL + "/graphql",
		RequestHeaders:  map[string]string{},
		ResponseHeaders: map[string]string{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != http.StatusForbidden || results[0].Error == "" {
		t.Fatalf("results = %#v", results)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

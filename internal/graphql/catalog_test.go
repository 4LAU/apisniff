package graphql

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func TestBuildCatalogGroupsByIdentity(t *testing.T) {
	mk := func(name, q string) model.CapturedFlow {
		return model.CapturedFlow{Method: "POST", Host: "api.x.com", Path: "/graphql", URL: "https://api.x.com/graphql",
			RequestHeaders: map[string]string{"content-type": "application/json"},
			RequestBody:    []byte(`{"operationName":"` + name + `","query":"` + q + `","variables":{"id":1}}`),
			ResponseStatus: 200, ResponseBody: []byte(`{"data":{"ok":true}}`)}
	}
	flows := []model.CapturedFlow{mk("GetA", "query GetA{a}"), mk("GetA", "query GetA{a}"), mk("GetB", "query GetB{b}")}
	cat := BuildCatalog(flows)
	if cat.OperationCount != 2 {
		t.Fatalf("want 2 ops, got %d", cat.OperationCount)
	}
	if cat.Operations[0].OperationName != "GetA" || cat.Operations[0].ObservedCount != 2 {
		t.Fatalf("agg: %+v", cat.Operations[0])
	}
	if cat.Operations[0].Source != "captured-query" {
		t.Fatalf("source")
	}
	if cat.Operations[0].Quality != "complete" {
		t.Fatalf("quality")
	}
}

func TestBuildCatalogTruncatedIsPartial(t *testing.T) {
	flow := model.CapturedFlow{Method: "POST", Host: "api.x.com", Path: "/graphql", URL: "https://api.x.com/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"Big","query":"query Big{x}"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{"x":`),
		Tags: []string{"response_body_truncated"}}
	cat := BuildCatalog([]model.CapturedFlow{flow})
	if cat.OperationCount != 1 {
		t.Fatalf("want 1")
	}
	op := cat.Operations[0]
	if op.Quality != "partial" {
		t.Fatalf("must be partial, got %q", op.Quality)
	}
	if op.ResponseSchema != nil {
		t.Fatalf("truncated response must not produce authoritative schema")
	}
}

func TestBuildCatalogPersistedHashSource(t *testing.T) {
	flow := model.CapturedFlow{Method: "POST", Host: "vrbo.com", Path: "/graphql", URL: "https://vrbo.com/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"Pay","extensions":{"persistedQuery":{"sha256Hash":"deadbeef"}}}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`)}
	cat := BuildCatalog([]model.CapturedFlow{flow})
	op := cat.Operations[0]
	if op.Source != "persisted-hash" || op.Query != nil {
		t.Fatalf("persisted: %+v", op)
	}
	if op.PersistedHash == nil || *op.PersistedHash != "deadbeef" {
		t.Fatalf("hash")
	}
	if op.OperationType != "unknown" {
		t.Fatalf("type must be unknown")
	}
}

func TestBuildCatalogAPQMismatchFlags(t *testing.T) {
	flow := model.CapturedFlow{Method: "POST", Host: "api.x.com", Path: "/graphql", URL: "https://api.x.com/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"Q","query":"query Q{q}","extensions":{"persistedQuery":{"sha256Hash":"0000notrealhash"}}}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`)}
	cat := BuildCatalog([]model.CapturedFlow{flow})
	if !cat.Operations[0].HashMismatch {
		t.Fatalf("APQ mismatch must be flagged")
	}
}

func TestBuildCatalogInvalidResponseJSONIsPartial(t *testing.T) {
	flow := model.CapturedFlow{Method: "POST", Host: "api.x.com", Path: "/graphql", URL: "https://api.x.com/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"Q","query":"query Q{q}"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{"q":`), // invalid JSON, NO truncation tag
	}
	cat := BuildCatalog([]model.CapturedFlow{flow})
	if cat.OperationCount != 1 {
		t.Fatalf("want 1")
	}
	op := cat.Operations[0]
	if op.Quality != "partial" {
		t.Fatalf("invalid-JSON response must be partial even without a tag, got %q", op.Quality)
	}
	if op.ResponseSchema != nil {
		t.Fatalf("invalid-JSON response must not produce an authoritative schema")
	}
}

// TestBuildCatalogTruncatedRequestQuerySkipped pins Gap 2: a non-authoritative
// request body must not donate its query text to the canonical Query. The two
// flows carry the SAME identity (endpoint, method, name, discriminator), so a
// truncated longer-vs-clean-shorter pair is NOT expressible — different query
// text yields a different discriminator hash and thus a different group. We
// therefore pin the unit invariant directly: a captured-query group whose only
// member has a truncated request must not surface that query.
func TestBuildCatalogTruncatedRequestQuerySkipped(t *testing.T) {
	flow := model.CapturedFlow{Method: "POST", Host: "api.x.com", Path: "/graphql", URL: "https://api.x.com/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"Big","query":"query Big{this_is_a_long_field}"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
		Tags: []string{"request_body_truncated"},
	}
	cat := BuildCatalog([]model.CapturedFlow{flow})
	if cat.OperationCount != 1 {
		t.Fatalf("want 1")
	}
	op := cat.Operations[0]
	if op.Quality != "partial" {
		t.Fatalf("truncated request must be partial, got %q", op.Quality)
	}
	if op.Query == nil || *op.Query != "" {
		t.Fatalf("truncated request must not donate its query to canonical Query, got %v", op.Query)
	}
}

func TestWriteCatalogStaleCleanup(t *testing.T) {
	dir := t.TempDir()
	must := func(n string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("graphql-operations.json")
	must("operations.graphql")
	if err := WriteCatalog(dir, BuildCatalog(nil)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"graphql-operations.json", "operations.graphql"} {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Fatalf("%s should be removed", n)
		}
	}
}

func TestWriteCatalogColludingNamesSuffixed(t *testing.T) {
	dir := t.TempDir()
	mk := func(host, q string) model.CapturedFlow {
		return model.CapturedFlow{Method: "POST", Host: host, Path: "/graphql", URL: "https://" + host + "/graphql",
			RequestHeaders: map[string]string{"content-type": "application/json"},
			RequestBody:    []byte(`{"operationName":"Dup","query":"` + q + `"}`),
			ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`)}
	}
	cat := BuildCatalog([]model.CapturedFlow{mk("a.com", "query Dup{a}"), mk("b.com", "query Dup{b}")})
	if err := WriteCatalog(dir, cat); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "operations.graphql"))
	if !strings.Contains(string(data), "Dup_") {
		t.Fatalf("colliding names must be suffixed in the .graphql file:\n%s", data)
	}
}

func TestWriteCatalogOmitsEmptyQueryDoc(t *testing.T) {
	dir := t.TempDir()
	// Truncated request -> canonical Query becomes empty (IR-4). The op still
	// exists in the JSON catalog, but the SDL must not carry an empty document.
	flow := model.CapturedFlow{Method: "POST", Host: "api.x.com", Path: "/graphql", URL: "https://api.x.com/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"Ghost","query":"query Ghost{x}"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
		Tags: []string{"request_body_truncated"},
	}
	cat := BuildCatalog([]model.CapturedFlow{flow})
	op := cat.Operations[0]
	if op.Query == nil || *op.Query != "" {
		t.Fatalf("precondition: truncated request must yield empty canonical Query, got %v", op.Query)
	}
	if err := WriteCatalog(dir, cat); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "operations.graphql"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Ghost") {
		t.Fatalf("op with empty query must be omitted from the SDL file, got:\n%q", data)
	}
}

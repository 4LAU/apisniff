package finalize

import (
	"os"
	"path/filepath"
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
	for _, n := range []string{"spec.yaml", "graphql-operations.json"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("missing %s: %v", n, err)
		}
	}
}

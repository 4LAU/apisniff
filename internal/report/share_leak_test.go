package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

// TestShareDoesNotLeakPathIDOrVariable is the IR-1 end-to-end regression: a
// GraphQL flow whose request PATH carries an opaque ID and whose VARIABLES carry
// a secret must produce share output where neither value appears in ANY file,
// while the normalized x-apisniff-graphql extension is still present in spec.yaml.
func TestShareDoesNotLeakPathIDOrVariable(t *testing.T) {
	// A realistic opaque ID (24-char hex) that the spec-path normalizer redacts
	// to a {param}. The literal value must never survive into share output.
	const pathID = "a1b2c3d4e5f6a7b8c9d0e1f2"
	const secret = "LEAKSECRET"
	bundleDir := t.TempDir()
	writeLeakBundle(t, bundleDir, pathID, secret)

	result, err := Share(ShareOptions{BundleOrDomain: bundleDir})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if len(result.Files) == 0 {
		t.Fatal("Share produced no files")
	}

	sawSpec := false
	for _, name := range result.Files {
		content := readFile(t, filepath.Join(result.OutputDir, name))
		if strings.Contains(content, pathID) {
			t.Errorf("path ID leaked into %s", name)
		}
		if strings.Contains(content, secret) {
			t.Errorf("variable secret leaked into %s", name)
		}
		if name == "spec.yaml" {
			sawSpec = true
			if !strings.Contains(content, "x-apisniff-graphql") {
				t.Errorf("spec.yaml missing x-apisniff-graphql extension")
			}
		}
	}
	if !sawSpec {
		t.Fatal("Share did not produce spec.yaml; GraphQL flow was filtered out")
	}
}

// writeLeakBundle plants session.json and a flows.jsonl with one GraphQL flow,
// using the model's own marshaling so bodies are base64-encoded as on disk.
func writeLeakBundle(t *testing.T, dir, pathID, secret string) {
	t.Helper()
	session := `{"domain":"api.x.com","total_flows":1,"kept_flows":1}`
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte(session), 0o600); err != nil {
		t.Fatal(err)
	}
	flow := model.CapturedFlow{
		Method:         "POST",
		Host:           "api.x.com",
		Path:           "/properties/" + pathID + "/graphql",
		URL:            "https://api.x.com/properties/" + pathID + "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"Q","query":"query Q{q}","variables":{"secret":"` + secret + `"}}`),
		ResponseStatus: 200,
		ResponseBody:   []byte(`{"data":{}}`),
	}
	line, err := flow.ToJSONL()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

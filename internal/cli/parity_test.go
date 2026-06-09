package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/report"
)

// 'apisniff spec' and 'apisniff share' must derive the spec — operations AND
// auth inference — from the same pipeline. Auth evidence here deliberately
// lives on a document flow (session cookie on an HTML page) that contributes
// no operation: parity must hold anyway.
func TestSpecAndShareEmitIdenticalSpecs(t *testing.T) {
	bundleDir := t.TempDir()
	apiFlow := `{"method":"GET","host":"example.com","path":"/api/users/123","url":"https://example.com/api/users/123","request_headers":{"authorization":"Bearer tok"},"response_status":200,"response_headers":{"content-type":"application/json"},"response_body":"eyJvayI6dHJ1ZX0=","_body_encoding":"base64","tags":[],"timestamp":2}`
	docFlow := `{"method":"GET","host":"example.com","path":"/account","url":"https://example.com/account","request_headers":{"cookie":"session=abc123"},"response_status":200,"response_headers":{"content-type":"text/html"},"response_body":"","_body_encoding":"base64","tags":[],"timestamp":1}`
	flowsPath := writeFlows(t, bundleDir, docFlow, apiFlow)
	session := `{"domain":"example.com","total_flows":2,"kept_flows":2}`
	if err := os.WriteFile(filepath.Join(bundleDir, "session.json"), []byte(session), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := executeForTest(newRootCommand(), "spec", "example.com", "-i", flowsPath, "-f", "yaml", "--infer-security-schemes")
	if err != nil {
		t.Fatal(err)
	}

	shareOut := filepath.Join(t.TempDir(), "share")
	if _, err := report.Share(report.ShareOptions{BundleOrDomain: bundleDir, OutputDir: shareOut}); err != nil {
		t.Fatal(err)
	}
	shared, err := os.ReadFile(filepath.Join(shareOut, "spec.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	cliSpec := strings.TrimSpace(stdout)
	shareSpec := strings.TrimSpace(string(shared))
	if cliSpec != shareSpec {
		t.Fatalf("spec and share emitted different specs:\n--- spec command ---\n%s\n--- share ---\n%s", cliSpec, shareSpec)
	}
	if !strings.Contains(cliSpec, "session_cookie") {
		t.Fatalf("auth evidence from the document flow was lost:\n%s", cliSpec)
	}
}

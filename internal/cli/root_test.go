package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/capture"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/spf13/cobra"
)

func TestReplayCommandExposesForwardAuthFlag(t *testing.T) {
	cmd := newReplayCommand()
	if cmd.Flags().Lookup("forward-auth") == nil {
		t.Fatalf("forward-auth flag missing")
	}
}

func TestAnalyzeHumanWritesOnlyStderrAndBundle(t *testing.T) {
	input := writeTestFlows(t, t.TempDir())
	outputDir := filepath.Join(t.TempDir(), "bundle")

	stdout, stderr, err := executeForTest(newAnalyzeCommand(), input, "--domain", "example.com", "--output-dir", outputDir)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertContains(t, stderr, "apisniff analyze", "bundle:", outputDir)
	for _, name := range []string{"session.json", "flows.jsonl", "report.md"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}

func TestAnalyzeJSONStdoutIsPure(t *testing.T) {
	input := writeTestFlows(t, t.TempDir())

	stdout, stderr, err := executeForTest(newAnalyzeCommand(), input, "--json")
	if err != nil {
		t.Fatalf("analyze --json returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	if payload["schema_version"].(float64) != 1 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestAnalyzeAutoDetectsDomain(t *testing.T) {
	input := writeFlows(t, t.TempDir(),
		`{"method":"GET","host":"api.mysite.com","path":"/v1/users","url":"https://api.mysite.com/v1/users","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
		`{"method":"GET","host":"cdn.mysite.com","path":"/asset.png","url":"https://cdn.mysite.com/asset.png","request_headers":{},"response_status":200,"response_headers":{"content-type":"image/png"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
	)

	stdout, stderr, err := executeForTest(newAnalyzeCommand(), input, "--json")
	if err != nil {
		t.Fatalf("analyze --json returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	if payload["domain"] != "mysite.com" {
		t.Fatalf("domain = %v", payload["domain"])
	}
}

func TestAnalyzeWarnsForAmbiguousAutoDetectedDomain(t *testing.T) {
	input := writeFlows(t, t.TempDir(),
		`{"method":"GET","host":"api.aaa.com","path":"/v1/x","url":"https://api.aaa.com/v1/x","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
		`{"method":"GET","host":"api.bbb.com","path":"/v1/x","url":"https://api.bbb.com/v1/x","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
	)

	stdout, stderr, err := executeForTest(newAnalyzeCommand(), input, "--json")
	if err != nil {
		t.Fatalf("analyze --json returned error: %v", err)
	}
	assertPureJSON(t, stdout)
	assertContains(t, stderr, "ambiguous domain", "aaa.com")
}

func TestAnalyzeFetchGraphQLRequiresOutputDir(t *testing.T) {
	input := writeTestFlows(t, t.TempDir())

	stdout, _, err := executeForTest(newAnalyzeCommand(), input, "--fetch-graphql")
	if err == nil {
		t.Fatalf("expected error")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(err.Error(), "--fetch-graphql requires --output-dir to store the introspection result") {
		t.Fatalf("error = %v", err)
	}
}

func TestSpecWritesSpecToStdoutAndStatusToStderr(t *testing.T) {
	input := writeTestFlows(t, t.TempDir())

	stdout, stderr, err := executeForTest(newSpecCommand(), "example.com", "--input", input, "--format", "json")
	if err != nil {
		t.Fatalf("spec returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not pure JSON spec: %v\n%s", err, stdout)
	}
	if payload["openapi"] != "3.0.3" {
		t.Fatalf("spec payload = %#v", payload)
	}
	assertContains(t, stderr, "apisniff spec", "paths:", "operations:")
}

func TestSpecOutputWritesOnlyStderrAndFiles(t *testing.T) {
	input := writeTestFlows(t, t.TempDir())
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.json")
	surfacePath := filepath.Join(dir, "surface.json")

	stdout, stderr, err := executeForTest(newSpecCommand(), "example.com", "--input", input, "--format", "json", "--output", specPath, "--surface-output", surfacePath)
	if err != nil {
		t.Fatalf("spec --output returned error: %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertContains(t, stderr, "apisniff spec", "wrote:", specPath, "surface:", surfacePath)
	assertJSONFile(t, specPath)
	assertJSONFile(t, surfacePath)
}

func TestSpecIncludeThirdPartySurvivesAPIFilter(t *testing.T) {
	input := writeFlows(t, t.TempDir(),
		`{"method":"GET","host":"example.com","path":"/api/users/123","url":"https://example.com/api/users/123","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
		`{"method":"GET","host":"partner.test","path":"/partner","url":"https://partner.test/partner","request_headers":{},"response_status":200,"response_headers":{"content-type":"text/plain"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
	)

	stdout, _, err := executeForTest(newSpecCommand(), "example.com", "--input", input, "--format", "json", "--include-third-party")
	if err != nil {
		t.Fatalf("spec returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	paths := payload["paths"].(map[string]any)
	if _, ok := paths["/partner"]; !ok {
		t.Fatalf("included third-party path missing from spec paths: %#v", paths)
	}
}

func TestSpecIncludeCategoryIncludesDroppedFlows(t *testing.T) {
	input := writeFlows(t, t.TempDir(),
		`{"method":"GET","host":"example.com","path":"/api/users/123","url":"https://example.com/api/users/123","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
		`{"method":"GET","host":"example.com","path":"/rum.gif","url":"https://example.com/rum.gif","request_headers":{},"response_status":200,"response_headers":{"content-type":"image/gif"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
	)

	stdout, _, err := executeForTest(newSpecCommand(), "example.com", "--input", input, "--format", "json", "--include-category", "telemetry")
	if err != nil {
		t.Fatalf("spec returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	paths := payload["paths"].(map[string]any)
	if _, ok := paths["/rum.gif"]; !ok {
		t.Fatalf("included telemetry path missing from spec paths: %#v", paths)
	}
}

func TestSpecIncludeHostIncludesDroppedFlows(t *testing.T) {
	input := writeFlows(t, t.TempDir(),
		`{"method":"GET","host":"example.com","path":"/api/users/123","url":"https://example.com/api/users/123","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
		`{"method":"GET","host":"partner.test","path":"/v1/data","url":"https://partner.test/v1/data","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"_body_encoding":"base64","tags":[],"timestamp":1}`,
	)

	stdout, _, err := executeForTest(newSpecCommand(), "example.com", "--input", input, "--format", "json", "--include-host", "partner.test")
	if err != nil {
		t.Fatalf("spec returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	paths := payload["paths"].(map[string]any)
	if _, ok := paths["/v1/data"]; !ok {
		t.Fatalf("included host path missing from spec paths: %#v", paths)
	}
}

func TestProbeRateRequiresURL(t *testing.T) {
	_, _, err := executeForTest(newProbeCommand(), "rate")
	if err == nil {
		t.Fatalf("expected error for probe rate without URL")
	}
	if !strings.Contains(err.Error(), "probe rate requires a URL argument") {
		t.Fatalf("error = %v", err)
	}
}

func TestShareJSONStdoutIsPure(t *testing.T) {
	bundle := t.TempDir()
	input := writeTestFlows(t, t.TempDir())
	if err := os.Rename(input, filepath.Join(bundle, "flows.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "session.json"), []byte(`{"domain":"example.com","total_flows":1,"kept_flows":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeForTest(newShareCommand(), bundle, "--json")
	if err != nil {
		t.Fatalf("share --json returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
}

func TestProbeJSONStdoutIsPure(t *testing.T) {
	stdout, stderr, err := executeForTest(newProbeCommand(), "http://127.0.0.1:1", "--json")
	if err != nil {
		t.Fatalf("probe --json returned error: %v", err)
	}
	assertPureJSON(t, stdout)
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestProbeRateJSONStdoutIsPure(t *testing.T) {
	stdout, stderr, err := executeForTest(newProbeCommand(), "rate", "http://127.0.0.1:1", "--json", "--rate-requests", "1")
	if err != nil {
		t.Fatalf("probe rate --json returned error: %v", err)
	}
	assertPureJSON(t, stdout)
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestReplayJSONStdoutIsPure(t *testing.T) {
	input := writeTestFlows(t, t.TempDir())

	stdout, stderr, err := executeForTest(newReplayCommand(), input, "--json", "--dry-run")
	if err != nil {
		t.Fatalf("replay --json returned error: %v", err)
	}
	assertPureJSON(t, stdout)
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestReconJSONStdoutIsPure(t *testing.T) {
	previous := captureRun
	t.Cleanup(func() { captureRun = previous })
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		return &capture.Result{
			BundleDir: "/tmp/apisniff/example",
			FlowsPath: "/tmp/apisniff/example/flows.jsonl",
			Stats: model.SessionStats{
				Domain:     "example.com",
				TotalFlows: 1,
				KeptFlows:  1,
				Dropped:    map[string]int{},
			},
		}, nil
	}

	stdout, stderr, err := executeForTest(newReconCommand(), "example.com", "--json")
	if err != nil {
		t.Fatalf("recon --json returned error: %v", err)
	}
	assertPureJSON(t, stdout)
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func executeForTest(cmd *cobra.Command, args ...string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SilenceUsage = true
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func writeTestFlows(t *testing.T, dir string) string {
	t.Helper()
	line := `{"method":"GET","host":"example.com","path":"/api/users/123","url":"https://example.com/api/users/123","request_headers":{},"response_status":200,"response_headers":{"content-type":"application/json"},"response_body":"eyJvayI6dHJ1ZX0=","_body_encoding":"base64","tags":["category:business_api"],"timestamp":1}`
	return writeFlows(t, dir, line)
}

func writeFlows(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	path := filepath.Join(dir, "flows.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertContains(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func assertJSONFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("%s was not JSON: %v", path, err)
	}
}

func assertPureJSON(t *testing.T, text string) {
	t.Helper()
	var payload any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, text)
	}
}

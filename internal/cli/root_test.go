package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/capture"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/spf13/cobra"
)

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
	assertContains(t, stderr, "apisniff analyze", "bundle", outputDir)
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

func TestAnalyzeImportsHARAndWritesBundleStructure(t *testing.T) {
	input := filepath.Join(t.TempDir(), "traffic.har")
	har := `{"log":{"entries":[
		{"startedDateTime":"2024-01-01T00:00:00Z","request":{"method":"GET","url":"https://api.example.com/v1/users","headers":[{"name":"User-Agent","value":"go-test"}]},"response":{"status":200,"headers":[{"name":"Content-Type","value":"application/json"}],"content":{"text":"{\"ok\":true}"}}},
		{"startedDateTime":"2024-01-01T00:00:01Z","request":{"method":"POST","url":"https://api.example.com/v1/items","headers":[]},"response":{"status":201,"headers":[{"name":"Content-Type","value":"application/json"}],"content":{"text":"{\"id\":1}"}}}
	]}}`
	if err := os.WriteFile(input, []byte(har), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(t.TempDir(), "bundle")

	stdout, _, err := executeForTest(newAnalyzeCommand(), input, "--domain", "example.com", "--output-dir", outputDir)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertAnalyzeBundle(t, outputDir, "example.com", 2)
	flows := readFlowLines(t, filepath.Join(outputDir, "flows.jsonl"))
	if len(flows) < 2 {
		t.Fatalf("expected 2 flows, got %d", len(flows))
	}
	if flows[0]["host"] != "api.example.com" || flows[0]["method"] != "GET" || flows[1]["method"] != "POST" {
		t.Fatalf("imported HAR flows = %#v", flows)
	}
}

func TestAnalyzeImportsBurpAndJSONL(t *testing.T) {
	t.Run("burp", func(t *testing.T) {
		input := filepath.Join(t.TempDir(), "traffic.xml")
		xml := `<?xml version="1.0"?><items>
			<item><method>POST</method><url>https://example.com/api/items?page=1</url><status>201</status><request>POST /api/items?page=1 HTTP/1.1&#13;&#10;Host: example.com&#13;&#10;Content-Type: application/json&#13;&#10;&#13;&#10;{"name":"widget"}</request><response>HTTP/1.1 201 Created&#13;&#10;Content-Type: application/json&#13;&#10;&#13;&#10;{"id":1}</response></item>
		</items>`
		if err := os.WriteFile(input, []byte(xml), 0o600); err != nil {
			t.Fatal(err)
		}
		outputDir := filepath.Join(t.TempDir(), "bundle")
		if _, _, err := executeForTest(newAnalyzeCommand(), input, "--domain", "example.com", "--output-dir", outputDir); err != nil {
			t.Fatalf("analyze burp returned error: %v", err)
		}
		assertAnalyzeBundle(t, outputDir, "example.com", 1)
		flows := readFlowLines(t, filepath.Join(outputDir, "flows.jsonl"))
		if len(flows) < 1 {
			t.Fatalf("expected at least 1 flow, got %d", len(flows))
		}
		if flows[0]["path"] != "/api/items?page=1" || flows[0]["response_status"].(float64) != 201 {
			t.Fatalf("imported Burp flow = %#v", flows[0])
		}
	})

	t.Run("jsonl", func(t *testing.T) {
		input := writeFlows(t, t.TempDir(),
			`{"method":"GET","host":"api.example.com","path":"/v1/items","url":"https://api.example.com/v1/items","request_headers":{"user-agent":"go-test"},"response_status":200,"response_headers":{"content-type":"application/json"},"response_body":"eyJpdGVtcyI6W119","_body_encoding":"base64","tags":["api_signal"],"timestamp":1715100000}`,
		)
		outputDir := filepath.Join(t.TempDir(), "bundle")
		if _, _, err := executeForTest(newAnalyzeCommand(), input, "--domain", "example.com", "--output-dir", outputDir); err != nil {
			t.Fatalf("analyze jsonl returned error: %v", err)
		}
		assertAnalyzeBundle(t, outputDir, "example.com", 1)
		session := readJSONFile[map[string]any](t, filepath.Join(outputDir, "session.json"))
		if session["kept_flows"] != session["total_flows"] {
			t.Fatalf("JSONL import should keep all flows: %#v", session)
		}
	})
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
	assertContains(t, stderr, "apisniff spec", "paths", "operations")
}

func TestSpecDefaultFormatWritesYAMLToStdout(t *testing.T) {
	input := writeTestFlows(t, t.TempDir())

	stdout, stderr, err := executeForTest(newSpecCommand(), "example.com", "--input", input)
	if err != nil {
		t.Fatalf("spec returned error: %v", err)
	}
	if !strings.Contains(stdout, "openapi: 3.0.3") {
		t.Fatalf("stdout did not contain YAML OpenAPI version:\n%s", stdout)
	}
	assertContains(t, stdout, "paths:", "/api/users/{userId}:")
	assertContains(t, stderr, "apisniff spec", "format", "yaml")
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
	assertContains(t, stderr, "apisniff spec", "wrote", specPath, "surface", surfacePath)
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

func TestSpecCommandIncludesHTMLFetchEndpoint(t *testing.T) {
	// A GET that returns HTML but was issued by fetch() (sec-fetch-dest: empty).
	// Such a request is API surface regardless of content-type: it must land in
	// the spec, and the coverage report must not flag it as excluded. Guards
	// against any regression that silently drops data-fetched HTML endpoints.
	flow := model.CapturedFlow{
		Method:          "GET",
		Host:            "www.example.com",
		Path:            "/bin/rewards-catalog/list",
		URL:             "https://www.example.com/bin/rewards-catalog/list",
		RequestHeaders:  map[string]string{"sec-fetch-dest": "empty", "sec-fetch-mode": "cors"},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "text/html"},
		ResponseBody:    []byte("<li class=tile data-brand=Acme></li>"),
	}
	line, err := flow.ToJSONL()
	if err != nil {
		t.Fatalf("marshal flow: %v", err)
	}
	input := writeFlows(t, t.TempDir(), line)

	// Spec body goes to stdout; the human status (including any "not in spec"
	// warning from WriteSpecStatus) goes to stderr via humanOutputConfig.
	specYAML, statusOutput, err := executeForTest(newSpecCommand(), "example.com", "--input", input, "--format", "yaml")
	if err != nil {
		t.Fatalf("spec returned error: %v", err)
	}

	// The spec must document the HTML endpoint as an operation.
	if !strings.Contains(specYAML, "/bin/rewards-catalog/list") {
		t.Fatalf("HTML endpoint missing from spec:\n%s", specYAML)
	}
	if !strings.Contains(specYAML, "text/html") {
		t.Fatalf("text/html response not documented in spec:\n%s", specYAML)
	}
	// And it must be represented, not flagged as excluded, in the status output.
	if strings.Contains(statusOutput, "not in spec") {
		t.Fatalf("HTML endpoint wrongly reported as excluded:\n%s", statusOutput)
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
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
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

func TestReconJSONIncludesFilteredPath(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		return &capture.Result{
			BundleDir:    "/tmp/apisniff/example",
			FlowsPath:    "/tmp/apisniff/example/flows.jsonl",
			FilteredPath: "/tmp/apisniff/example/filtered.jsonl",
			Stats: model.SessionStats{
				Domain:     "example.com",
				TotalFlows: 5,
				KeptFlows:  2,
				Dropped: map[string]int{
					"telemetry": 2,
					"static":    1,
				},
			},
		}, nil
	}

	stdout, stderr, err := executeForTest(newReconCommand(), "example.com", "--json")
	if err != nil {
		t.Fatalf("recon --json returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	if payload["filtered_path"] != "/tmp/apisniff/example/filtered.jsonl" {
		t.Fatalf("filtered_path = %v", payload["filtered_path"])
	}
}

func TestReconJSONOmitsFilteredPathWhenWriterFailed(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		return &capture.Result{
			BundleDir: "/tmp/apisniff/example",
			FlowsPath: "/tmp/apisniff/example/flows.jsonl",
			Stats: model.SessionStats{
				Domain:     "example.com",
				TotalFlows: 4,
				KeptFlows:  1,
				Dropped: map[string]int{
					"telemetry": 3,
				},
			},
		}, nil
	}

	stdout, stderr, err := executeForTest(newReconCommand(), "example.com", "--json")
	if err != nil {
		t.Fatalf("recon --json returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	if _, ok := payload["filtered_path"]; ok {
		t.Fatalf("filtered_path present when capture result left it empty: %#v", payload)
	}
	stats := payload["stats"].(map[string]any)
	dropped := stats["dropped"].(map[string]any)
	if int(dropped["telemetry"].(float64)) != 3 {
		t.Fatalf("dropped telemetry = %v, want 3", dropped["telemetry"])
	}
}

func TestReconHumanReportsFilteredCountAndPath(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		return &capture.Result{
			BundleDir:    "/tmp/apisniff/example",
			FlowsPath:    "/tmp/apisniff/example/flows.jsonl",
			FilteredPath: "/tmp/apisniff/example/filtered.jsonl",
			Stats: model.SessionStats{
				Domain:     "example.com",
				TotalFlows: 5,
				KeptFlows:  2,
				Dropped: map[string]int{
					"telemetry": 2,
					"static":    1,
				},
			},
		}, nil
	}

	stdout, stderr, err := executeForTest(newReconCommand(), "example.com")
	if err != nil {
		t.Fatalf("recon returned error: %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertContains(t, stderr, "3 filtered", "/tmp/apisniff/example/filtered.jsonl")
}

func TestReconDefaultModeIsProxy(t *testing.T) {
	cmd := newReconCommand()
	flag := cmd.Flags().Lookup("mode")
	if flag == nil {
		t.Fatal("--mode flag not defined")
	}
	if flag.DefValue != "proxy" {
		t.Fatalf("--mode default = %q, want proxy", flag.DefValue)
	}
}

func TestReconDefaultConfig(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }

	for _, tc := range []struct {
		name       string
		args       []string
		wantMode   string
		wantLaunch bool
		wantPort   int // effective Config.Port (0 = ephemeral, resolved in CaptureProxy)
	}{
		{"default", []string{"example.com"}, "proxy", true, 0},
		{"no-browser", []string{"example.com", "--no-browser"}, "proxy", false, 8080},
		{"cdp-launch", []string{"example.com", "--mode", "cdp-launch"}, "cdp-launch", false, 0},
		{"cdp-attach", []string{"example.com", "--mode", "cdp-attach"}, "cdp-attach", false, 9222},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got capture.Config
			captureRun = func(_ context.Context, cfg capture.Config) (*capture.Result, error) {
				got = cfg
				return &capture.Result{
					BundleDir: "/tmp/apisniff/example",
					FlowsPath: "/tmp/apisniff/example/flows.jsonl",
					Stats:     model.SessionStats{Domain: "example.com", Dropped: map[string]int{}},
				}, nil
			}
			if _, _, err := executeForTest(newReconCommand(), tc.args...); err != nil {
				t.Fatalf("recon returned error: %v", err)
			}
			if got.Mode != tc.wantMode {
				t.Errorf("Mode = %q, want %q", got.Mode, tc.wantMode)
			}
			if got.LaunchBrowser != tc.wantLaunch {
				t.Errorf("LaunchBrowser = %v, want %v", got.LaunchBrowser, tc.wantLaunch)
			}
			if got.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tc.wantPort)
			}
		})
	}
}

func TestReconWarnsCookiesNotCapturedInCDPMode(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		return &capture.Result{
			BundleDir: "/tmp/apisniff/example",
			FlowsPath: "/tmp/apisniff/example/flows.jsonl",
			Stats:     model.SessionStats{Domain: "example.com", Dropped: map[string]int{}},
		}, nil
	}

	for _, mode := range []string{"cdp-launch", "cdp-attach"} {
		t.Run(mode, func(t *testing.T) {
			_, stderr, err := executeForTest(newReconCommand(), "example.com", "--mode", mode)
			if err != nil {
				t.Fatalf("recon returned error: %v", err)
			}
			assertContains(t, stderr, "does not capture", "proxy mode")
		})
	}
}

func TestReconProxyModeHasNoCookieWarning(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		return &capture.Result{
			BundleDir: "/tmp/apisniff/example",
			FlowsPath: "/tmp/apisniff/example/flows.jsonl",
			Stats:     model.SessionStats{Domain: "example.com", Dropped: map[string]int{}},
		}, nil
	}

	_, stderr, err := executeForTest(newReconCommand(), "example.com")
	if err != nil {
		t.Fatalf("recon returned error: %v", err)
	}
	if strings.Contains(stderr, "does not capture") {
		t.Fatalf("proxy (default) mode should not warn about cookies; stderr=%q", stderr)
	}
}

func TestReconJSONNullsStatusWriter(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	for _, tc := range []struct {
		name    string
		args    []string
		wantNil bool
	}{
		{"json nulls status writer", []string{"example.com", "--json"}, true},
		{"human keeps status writer", []string{"example.com"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got capture.Config
			captureRun = func(_ context.Context, cfg capture.Config) (*capture.Result, error) {
				got = cfg
				return &capture.Result{
					BundleDir: "/tmp/apisniff/example",
					FlowsPath: "/tmp/apisniff/example/flows.jsonl",
					Stats:     model.SessionStats{Domain: "example.com", Dropped: map[string]int{}},
				}, nil
			}
			if _, _, err := executeForTest(newReconCommand(), tc.args...); err != nil {
				t.Fatalf("recon returned error: %v", err)
			}
			if (got.StatusWriter == nil) != tc.wantNil {
				t.Errorf("StatusWriter nil = %v, want %v", got.StatusWriter == nil, tc.wantNil)
			}
		})
	}
}

func TestReconJSONSuppressesAdvisoryNotes(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		return &capture.Result{
			BundleDir: "/tmp/apisniff/example",
			FlowsPath: "/tmp/apisniff/example/flows.jsonl",
			Stats:     model.SessionStats{Domain: "example.com", Dropped: map[string]int{}},
		}, nil
	}
	for _, args := range [][]string{
		{"example.com", "--json"},
		{"example.com", "--json", "--mode", "cdp-launch"},
	} {
		_, stderr, err := executeForTest(newReconCommand(), args...)
		if err != nil {
			t.Fatalf("recon %v returned error: %v", args, err)
		}
		if stderr != "" {
			t.Fatalf("args %v: --json must suppress advisory notes; stderr=%q", args, stderr)
		}
	}
}

func TestReconBindGuardRejectsCDPModes(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	var ran bool
	captureRun = func(_ context.Context, _ capture.Config) (*capture.Result, error) {
		ran = true
		return &capture.Result{Stats: model.SessionStats{Domain: "example.com", Dropped: map[string]int{}}}, nil
	}
	for _, tc := range []struct {
		name string
		mode string
		args []string
	}{
		{"bind", "cdp-launch", []string{"example.com", "--mode", "cdp-launch", "--bind", "0.0.0.0"}},
		{"allow-client", "cdp-attach", []string{"example.com", "--mode", "cdp-attach", "--allow-client", "1.2.3.4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ran = false
			_, _, err := executeForTest(newReconCommand(), tc.args...)
			if err == nil {
				t.Fatal("expected --bind/--allow-client in cdp mode to be rejected, got nil")
			}
			if !strings.Contains(err.Error(), "proxy mode only") {
				t.Fatalf("error %q does not explain the guard", err)
			}
			if ran {
				t.Fatal("capture ran despite the guard rejecting the flags")
			}
		})
	}
}

func TestReconPassesBindAndAllowClient(t *testing.T) {
	previous := captureRun
	previousCount := bundleCountOlderThan
	t.Cleanup(func() {
		captureRun = previous
		bundleCountOlderThan = previousCount
	})
	bundleCountOlderThan = func(time.Duration) (int, error) { return 0, nil }
	var got capture.Config
	captureRun = func(_ context.Context, cfg capture.Config) (*capture.Result, error) {
		got = cfg
		return &capture.Result{
			BundleDir: "/tmp/apisniff/example",
			FlowsPath: "/tmp/apisniff/example/flows.jsonl",
			Stats:     model.SessionStats{Domain: "example.com", Dropped: map[string]int{}},
		}, nil
	}
	if _, _, err := executeForTest(newReconCommand(), "example.com", "--no-browser",
		"--bind", "192.168.1.10",
		"--allow-client", "192.168.1.50",
		"--allow-client", "10.0.0.1"); err != nil {
		t.Fatalf("recon returned error: %v", err)
	}
	if got.BindHost != "192.168.1.10" {
		t.Fatalf("BindHost = %q, want 192.168.1.10", got.BindHost)
	}
	if len(got.AllowedClients) != 2 || got.AllowedClients[0] != "192.168.1.50" || got.AllowedClients[1] != "10.0.0.1" {
		t.Fatalf("AllowedClients = %v, want [192.168.1.50 10.0.0.1]", got.AllowedClients)
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

func assertAnalyzeBundle(t *testing.T, outputDir string, domain string, totalFlows int) {
	t.Helper()
	for _, name := range []string{"session.json", "flows.jsonl", "report.md"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	session := readJSONFile[map[string]any](t, filepath.Join(outputDir, "session.json"))
	if session["domain"] != domain {
		t.Fatalf("session domain = %v, want %s", session["domain"], domain)
	}
	if int(session["total_flows"].(float64)) != totalFlows {
		t.Fatalf("session total_flows = %v, want %d", session["total_flows"], totalFlows)
	}
}

func readFlowLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var flows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var flow map[string]any
		if err := json.Unmarshal([]byte(line), &flow); err != nil {
			t.Fatalf("invalid flow JSONL: %v\n%s", err, line)
		}
		flows = append(flows, flow)
	}
	return flows
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		raw       string
		domain    string
		launchURL string
	}{
		{"example.com", "example.com", "https://example.com"},
		{"example.com/api", "example.com", "https://example.com/api"},
		{"example.com/api?x=1", "example.com", "https://example.com/api?x=1"},
		{"https://example.com/api", "example.com", "https://example.com/api"},
		{"https://example.com?x=1", "example.com", "https://example.com?x=1"},
		{"https://example.com#pricing", "example.com", "https://example.com#pricing"},
		{"example.com:8443/api", "example.com:8443", "https://example.com:8443/api"},
	}
	for _, tc := range cases {
		domain, launchURL := normalizeTarget(tc.raw)
		if domain != tc.domain || launchURL != tc.launchURL {
			t.Errorf("normalizeTarget(%q) = (%q, %q), want (%q, %q)", tc.raw, domain, launchURL, tc.domain, tc.launchURL)
		}
	}
}

func readJSONFile[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("%s was not JSON: %v", path, err)
	}
	return value
}

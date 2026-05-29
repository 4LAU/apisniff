package cli

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/bundle"
	"github.com/4LAU/apisniff/internal/capture"
	"github.com/4LAU/apisniff/internal/model"
)

func TestBundlesEmptyDirMessage(t *testing.T) {
	restoreBundleStubs(t)
	bundleList = func() ([]bundle.Bundle, error) { return nil, nil }

	stdout, stderr, err := executeForTest(newBundlesCommand())
	if err != nil {
		t.Fatalf("bundles returned error: %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertContains(t, stderr, "apisniff bundles", "No capture bundles found")
}

func TestBundlesJSONOmitsEmptyDomainAndSafeName(t *testing.T) {
	restoreBundleStubs(t)
	bundleList = func() ([]bundle.Bundle, error) {
		return []bundle.Bundle{{
			Path:       "/tmp/apisniff/unknown",
			CapturedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
			SizeBytes:  12,
			FlowCount:  3,
		}}, nil
	}

	stdout, stderr, err := executeForTest(newBundlesCommand(), "--json")
	if err != nil {
		t.Fatalf("bundles --json returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	bundles := payload["bundles"].([]any)
	first := bundles[0].(map[string]any)
	if _, ok := first["domain"]; ok {
		t.Fatalf("domain should be omitted when empty: %#v", first)
	}
	if _, ok := first["safe_name"]; ok {
		t.Fatalf("safe_name should be omitted when empty: %#v", first)
	}
}

func TestBundlesDefaultDoesNotReadFlowsJSONL(t *testing.T) {
	restoreBundleStubs(t)
	bundleList = func() ([]bundle.Bundle, error) {
		return []bundle.Bundle{{Path: "/tmp/apisniff/example", Domain: "example.com"}}, nil
	}
	loadJSONL = func(path string) ([]model.CapturedFlow, error) {
		return nil, errors.New("flows.jsonl should not be read by default")
	}

	_, _, err := executeForTest(newBundlesCommand(), "--json")
	if err != nil {
		t.Fatalf("bundles --json returned error: %v", err)
	}
}

func TestBundlesCredentialsReadsFlowsAndMapsLabels(t *testing.T) {
	restoreBundleStubs(t)
	dir := t.TempDir()
	bundleList = func() ([]bundle.Bundle, error) {
		return []bundle.Bundle{{Path: dir, Domain: "example.com"}}, nil
	}
	var loadedPath string
	loadJSONL = func(path string) ([]model.CapturedFlow, error) {
		loadedPath = path
		return []model.CapturedFlow{
			{RequestHeaders: map[string]string{"Authorization": "Bearer token"}, Path: "/api"},
			{RequestHeaders: map[string]string{"Authorization": "Basic token"}, Path: "/api"},
			{RequestHeaders: map[string]string{"X-API-Key": "key"}, Path: "/api"},
			{RequestHeaders: map[string]string{"Cookie": "session=abc"}, Path: "/api"},
			{RequestHeaders: map[string]string{}, Path: "/oauth/token"},
		}, nil
	}

	stdout, stderr, err := executeForTest(newBundlesCommand(), "--json", "--credentials")
	if err != nil {
		t.Fatalf("bundles --credentials returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if loadedPath != filepath.Join(dir, "flows.jsonl") {
		t.Fatalf("loaded path = %q", loadedPath)
	}
	var payload struct {
		Bundles []struct {
			Credentials []string `json:"credentials"`
		} `json:"bundles"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	got := strings.Join(payload.Bundles[0].Credentials, ",")
	want := "bearer,basic,api_key,cookies,oauth"
	if got != want {
		t.Fatalf("credentials = %q, want %q", got, want)
	}
}

func TestReconAgeWarningStaysOnStderr(t *testing.T) {
	restoreBundleStubs(t)
	previousCaptureRun := captureRun
	t.Cleanup(func() { captureRun = previousCaptureRun })
	bundleCountOlderThan = func(time.Duration) (int, error) { return 2, nil }
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
	assertContains(t, stderr, "older than 30 days", "apisniff clean --older-than 30d")
}

func restoreBundleStubs(t *testing.T) {
	t.Helper()
	previousList := bundleList
	previousDir := bundleDir
	previousLoadJSONL := loadJSONL
	previousDelete := bundleDelete
	previousCountOlderThan := bundleCountOlderThan
	previousNow := nowUTC
	t.Cleanup(func() {
		bundleList = previousList
		bundleDir = previousDir
		loadJSONL = previousLoadJSONL
		bundleDelete = previousDelete
		bundleCountOlderThan = previousCountOlderThan
		nowUTC = previousNow
	})
}

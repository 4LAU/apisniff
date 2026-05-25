package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/4LAU/apisniff-go/internal/auth"
	"github.com/4LAU/apisniff-go/internal/model"
	"github.com/4LAU/apisniff-go/internal/replay"
)

func testConfig(t *testing.T, buf *bytes.Buffer) Config {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	return Config{Color: false, Width: 72, Writer: buf}
}

func assertContains(t *testing.T, got string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(got, value) {
			t.Fatalf("output missing %q:\n%s", value, got)
		}
	}
}

func assertNoANSI(t *testing.T, got string) {
	t.Helper()
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("output contains ANSI escapes:\n%q", got)
	}
}

func TestWriteAnalyzeHumanNoColor(t *testing.T) {
	var buf bytes.Buffer
	result := AnalyzeResult{
		Domain:     "api.example.com",
		TotalFlows: 3,
		TopEndpoints: []EndpointSummary{
			{Method: "GET", Path: "/v1/users/{id}", Count: 2},
			{Method: "POST", Path: "/v1/login", Count: 1},
		},
		AuthPatterns: []auth.Pattern{{AuthType: "bearer", Detail: "authorization: bearer", FlowCount: 2}},
		Cookies:      []auth.ExtractedCookie{{Name: "session", Domain: "api.example.com", Path: "/", Source: "response"}},
	}

	if err := WriteAnalyze(testConfig(t, &buf), result); err != nil {
		t.Fatalf("WriteAnalyze returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertContains(t, got,
		"apisniff analyze",
		"domain:",
		"api.example.com",
		"flows:",
		"3",
		"Top endpoints",
		"[GET]",
		"/v1/users/{id}",
		"Auth patterns",
		"authorization: bearer",
		"Cookies",
		"session",
	)
}

func TestWriteProbeHumanNoColor(t *testing.T) {
	var buf bytes.Buffer
	assessment := &model.ProbeAssessment{
		URL:            "https://api.example.com",
		Verdict:        model.ClientDependent,
		Recommendation: "Use recon when browser-only checks differ from raw HTTP probes.",
		Results: []model.ProbeResult{
			{Variant: "browser", Status: 200, Latency: 1234 * time.Microsecond},
			{Variant: "raw", Status: 403, Latency: 5 * time.Millisecond, Body: []byte("captcha")},
		},
		Vendors: []model.VendorMatch{{Vendor: "cloudflare", Confidence: "high"}},
		GraphQL: &model.GraphQLResult{Endpoints: []string{"/graphql"}, Introspection: true},
		RateLimit: &model.RateLimitResult{
			RequestsSent: 20,
			FirstBlockAt: 12,
			BlockStatus:  429,
			MedianMS:     9.5,
		},
	}

	if err := WriteProbe(testConfig(t, &buf), assessment); err != nil {
		t.Fatalf("WriteProbe returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertContains(t, got,
		"apisniff probe",
		"https://api.example.com",
		"[client_dependent]",
		"cloudflare(high)",
		"introspection=true",
		"block_status=429",
		"Probe variants",
		"browser",
		"[200]",
		"raw",
		"[403]",
		"Recommendation",
	)

}

func TestStyleWidthClampAndTruncate(t *testing.T) {
	var buf bytes.Buffer
	s := newStyles(Config{Color: false, Width: 500, Writer: &buf})
	if s.cfg.Width != 120 {
		t.Fatalf("width = %d, want 120", s.cfg.Width)
	}
	got := truncate("abcdefghijklmnopqrstuvwxyz", 10)
	if len(got) > 10 {
		t.Fatalf("truncated value length = %d, want <= 10: %q", len(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("truncated value = %q, want ellipsis", got)
	}
}

func TestWriteReplayHumanNoColor(t *testing.T) {
	var buf bytes.Buffer
	summary := replay.Summary{
		Domain:  "api.example.com",
		Summary: map[string]int{"match": 1, "blocked": 1},
		Results: []replay.Result{
			{Method: "GET", Path: "/v1/users", OriginalStatus: 200, ReplayedStatus: 200, Category: "match"},
			{Method: "GET", Path: "/v1/orders", OriginalStatus: 200, ReplayedStatus: 403, Category: "blocked"},
		},
	}

	if err := WriteReplay(testConfig(t, &buf), summary); err != nil {
		t.Fatalf("WriteReplay returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertContains(t, got,
		"apisniff replay",
		"api.example.com",
		"Summary",
		"match:",
		"blocked:",
		"Results",
		"[GET]",
		"/v1/orders",
		"[200 -> 403]",
	)
}

func TestWriteMiscHumanNoColor(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRecon(testConfig(t, &buf), ReconResult{
		Domain:    "api.example.com",
		BundleDir: "/tmp/apisniff/api",
		FlowsPath: "/tmp/apisniff/api/flows.jsonl",
		KeptFlows: 8,
	}); err != nil {
		t.Fatalf("WriteRecon returned error: %v", err)
	}
	if err := WriteSpecStatus(testConfig(t, &buf), SpecStatusResult{
		Domain:     "api.example.com",
		Format:     "yaml",
		OutputPath: "spec.yaml",
		Paths:      4,
		Operations: 6,
	}); err != nil {
		t.Fatalf("WriteSpecStatus returned error: %v", err)
	}
	if err := WriteShare(testConfig(t, &buf), ShareResult{
		OutputDir: "/tmp/share",
		Files:     []string{"spec.yaml", "inventory.json"},
	}); err != nil {
		t.Fatalf("WriteShare returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertContains(t, got,
		"apisniff recon",
		"captured:",
		"8 flows",
		"apisniff spec",
		"wrote:",
		"spec.yaml",
		"operations:",
		"6",
		"apisniff share",
		"inventory.json",
	)
}

package output

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/replay"
)

func testConfig(t *testing.T, buf *bytes.Buffer) Config {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	return Config{Color: false, Unicode: true, Width: 72, Writer: buf}
}

func assertContains(t *testing.T, got string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(got, value) {
			t.Fatalf("output missing %q:\n%s", value, got)
		}
	}
}

func assertNotContains(t *testing.T, got string, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(got, value) {
			t.Fatalf("output contains %q:\n%s", value, got)
		}
	}
}

func assertNoANSI(t *testing.T, got string) {
	t.Helper()
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("output contains ANSI escapes:\n%q", got)
	}
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

func stripANSIForTest(value string) string {
	return ansiPattern.ReplaceAllString(value, "")
}

func assertLinesWithinWidth(t *testing.T, got string, width int) {
	t.Helper()
	for _, line := range strings.Split(stripANSIForTest(got), "\n") {
		if line == "" {
			continue
		}
		if w := len([]rune(line)); w > width {
			t.Fatalf("line width = %d, want <= %d:\n%s\nfull output:\n%s", w, width, line, got)
		}
	}
}

func assertASCIIOnly(t *testing.T, got string) {
	t.Helper()
	for _, r := range got {
		if r > 127 {
			t.Fatalf("output contains non-ASCII rune %q:\n%s", r, got)
		}
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
		"api.example.com",
		"flows",
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

func TestWriteAnalyzeEmptyEndpointsShowsNone(t *testing.T) {
	var buf bytes.Buffer
	result := AnalyzeResult{Domain: "api.example.com", TotalFlows: 0}

	if err := WriteAnalyze(testConfig(t, &buf), result); err != nil {
		t.Fatalf("WriteAnalyze returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertContains(t, got, "apisniff analyze", "flows", "0", "endpoints", "0")
	if strings.Contains(got, "Top endpoints") || strings.Contains(got, "none") {
		t.Fatalf("empty sections should be omitted:\n%s", got)
	}
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
		"[CLIENT DEPENDENT]",
		"cloudflare (high)",
		"introspection=true",
		"block_status=429",
		"browser",
		"200",
		"raw",
		"403",
		"Recommendation",
	)

}

func TestStyleWidthClampAndTruncate(t *testing.T) {
	var buf bytes.Buffer
	s := newStyles(Config{Color: false, Unicode: true, Width: 500, Writer: &buf})
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
		"match",
		"blocked",
		"[GET]",
		"/v1/orders",
		"200 → 403",
	)
}

func TestWriteReplayDryRunHumanNoColor(t *testing.T) {
	var buf bytes.Buffer
	summary := replay.Summary{
		Domain:    "api.example.com",
		Mode:      "dry_run",
		Summary:   map[string]int{"safe": 2, "unsafe": 1, "total": 3},
		Endpoints: []string{"GET /v1/users", "POST /v1/orders"},
	}

	if err := WriteReplay(testConfig(t, &buf), summary); err != nil {
		t.Fatalf("WriteReplay returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertContains(t, got,
		"apisniff replay dry run",
		"safe",
		"2",
		"unsafe",
		"1",
		"total",
		"3",
		"Endpoints",
		"GET /v1/users",
	)
}

func TestWriteProbeRejectsNilAssessment(t *testing.T) {
	var buf bytes.Buffer
	err := WriteProbe(testConfig(t, &buf), nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "probe assessment is nil") {
		t.Fatalf("error = %v", err)
	}
	if buf.String() != "" {
		t.Fatalf("buffer = %q, want empty", buf.String())
	}
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
		"✓ captured",
		"8 flows",
		"apisniff spec",
		"✓ wrote",
		"spec.yaml",
		"operations",
		"6",
		"apisniff share",
		"inventory.json",
	)
}

func TestWriteReconFilteredOutput(t *testing.T) {
	t.Run("filtered count and path", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteRecon(testConfig(t, &buf), ReconResult{
			Domain:        "api.example.com",
			BundleDir:     "/tmp/apisniff/api",
			FlowsPath:     "/tmp/apisniff/api/flows.jsonl",
			FilteredPath:  "/tmp/apisniff/api/flows.filtered.jsonl",
			KeptFlows:     45,
			TotalFlows:    287,
			FilteredFlows: 242,
		})
		if err != nil {
			t.Fatalf("WriteRecon returned error: %v", err)
		}

		got := buf.String()
		assertNoANSI(t, got)
		assertContains(t, got,
			"✓ captured 45 flows (287 observed, 242 filtered)",
			"Bundle",
			"filtered",
			"/tmp/apisniff/api/flows.filtered.jsonl",
		)
	})

	t.Run("omits filtered fields when zero", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteRecon(testConfig(t, &buf), ReconResult{
			Domain:     "api.example.com",
			BundleDir:  "/tmp/apisniff/api",
			FlowsPath:  "/tmp/apisniff/api/flows.jsonl",
			KeptFlows:  8,
			TotalFlows: 8,
		})
		if err != nil {
			t.Fatalf("WriteRecon returned error: %v", err)
		}

		got := buf.String()
		assertNoANSI(t, got)
		assertContains(t, got, "✓ captured 8 flows")
		assertNotContains(t, got, "filtered", "observed")
	})

	t.Run("shows filtered count without path", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteRecon(testConfig(t, &buf), ReconResult{
			Domain:        "api.example.com",
			BundleDir:     "/tmp/apisniff/api",
			FlowsPath:     "/tmp/apisniff/api/flows.jsonl",
			KeptFlows:     8,
			FilteredFlows: 2,
		})
		if err != nil {
			t.Fatalf("WriteRecon returned error: %v", err)
		}

		got := buf.String()
		assertNoANSI(t, got)
		assertContains(t, got, "✓ captured 8 flows (2 filtered)")
		assertNotContains(t, got, "\n  filtered", "flows.filtered.jsonl")
	})
}

func TestProbeCompactTableAtNarrowWidthPreservesLatency(t *testing.T) {
	var buf bytes.Buffer
	assessment := &model.ProbeAssessment{
		URL:     "https://api.example.com",
		Verdict: model.FullBlock,
		Results: []model.ProbeResult{
			{Variant: "naked", Status: 403, Latency: 999 * time.Millisecond},
			{Variant: "impersonated", Status: 200, Latency: 226 * time.Millisecond},
		},
	}

	cfg := testConfig(t, &buf)
	cfg.Width = 40
	if err := WriteProbe(cfg, assessment); err != nil {
		t.Fatalf("WriteProbe returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertLinesWithinWidth(t, got, 40)
	assertContains(t, got, "Result", "999ms", "226ms")
	if strings.Contains(got, "Latency") {
		t.Fatalf("compact table should collapse latency column:\n%s", got)
	}
}

func TestUnicodeFalseUsesASCIIFallbacks(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Color: false, Unicode: false, Width: 72, Writer: &buf}
	if err := WriteShare(cfg, ShareResult{OutputDir: "/tmp/share", Files: []string{"spec.yaml"}}); err != nil {
		t.Fatalf("WriteShare returned error: %v", err)
	}

	got := buf.String()
	assertNoANSI(t, got)
	assertASCIIOnly(t, got)
	assertContains(t, got, "[OK] exported 1 files", "+", "|")
}

func TestLatencyBarAndResultIconFallbacks(t *testing.T) {
	s := newStyles(Config{Color: false, Unicode: true, Width: 80, Writer: io.Discard})
	if got := s.resultIcon(false, false); got != "✓ passed" {
		t.Fatalf("resultIcon passed = %q", got)
	}
	if got := s.resultIcon(true, false); got != "✗ blocked" {
		t.Fatalf("resultIcon blocked = %q", got)
	}
	if got := s.resultIcon(true, true); got != "⚡ challenge" {
		t.Fatalf("resultIcon challenge = %q", got)
	}
	if got := s.latencyBar(50, 100, 10); !strings.Contains(got, "50ms") || !strings.Contains(got, "█") {
		t.Fatalf("latencyBar = %q", got)
	}

	ascii := newStyles(Config{Color: false, Unicode: false, Width: 80, Writer: io.Discard})
	if got := ascii.resultIcon(true, false); got != "BLOCKED" {
		t.Fatalf("ASCII resultIcon = %q", got)
	}
	if got := ascii.latencyBar(50, 100, 10); !strings.Contains(got, "#") || strings.Contains(got, "█") {
		t.Fatalf("ASCII latencyBar = %q", got)
	}
}

func TestProbeWithColorEmitsANSI(t *testing.T) {
	var buf bytes.Buffer
	assessment := &model.ProbeAssessment{
		URL:     "https://api.example.com",
		Verdict: model.FullBlock,
		Results: []model.ProbeResult{
			{Variant: "naked", Status: 403, Latency: 500 * time.Millisecond},
		},
	}
	cfg := Config{Color: true, Unicode: true, Width: 80, Writer: &buf}
	if err := WriteProbe(cfg, assessment); err != nil {
		t.Fatalf("WriteProbe returned error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "\x1b[") {
		t.Fatalf("Color=true output missing ANSI escapes:\n%s", got)
	}
	assertContains(t, got, "apisniff probe", "naked")
}

func TestReplayUnicodeFalseUsesASCIIArrows(t *testing.T) {
	var buf bytes.Buffer
	summary := replay.Summary{
		Domain:  "api.example.com",
		Summary: map[string]int{"match": 1},
		Results: []replay.Result{
			{Method: "GET", Path: "/v1/users", OriginalStatus: 200, ReplayedStatus: 200, Category: "match"},
		},
	}
	cfg := Config{Color: false, Unicode: false, Width: 72, Writer: &buf}
	if err := WriteReplay(cfg, summary); err != nil {
		t.Fatalf("WriteReplay returned error: %v", err)
	}
	got := buf.String()
	assertNoANSI(t, got)
	assertASCIIOnly(t, got)
	assertContains(t, got, "200 -> 200", "ok match")
}

func TestLayoutAtBoundaryWidths(t *testing.T) {
	for _, width := range []int{40, 80, 120} {
		t.Run(fmt.Sprintf("width_%d", width), func(t *testing.T) {
			var buf bytes.Buffer
			cfg := Config{Color: false, Unicode: true, Width: width, Writer: &buf}
			err := WriteAnalyze(cfg, AnalyzeResult{
				Domain:     "api.example.com",
				TotalFlows: 3,
				TopEndpoints: []EndpointSummary{
					{Method: "GET", Path: "/v1/users/{id}/with/a/long/path", Count: 2},
					{Method: "POST", Path: "/v1/login", Count: 1},
				},
			})
			if err != nil {
				t.Fatalf("WriteAnalyze returned error: %v", err)
			}
			got := buf.String()
			assertLinesWithinWidth(t, got, width)
			assertContains(t, got, "Top endpoints", "Method", "Path", "Count")
		})
	}
}

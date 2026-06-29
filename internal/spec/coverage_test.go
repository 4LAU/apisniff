package spec

import (
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func TestBuildCoverageFlagsExcludedEndpoint(t *testing.T) {
	apiFlows := []model.CapturedFlow{
		{Method: "GET", Host: "example.com", Path: "/api/v1/users", ResponseStatus: 200, ResponseHeaders: map[string]string{"content-type": "application/json"}},
		{Method: "GET", Host: "example.com", Path: "/bin/list", ResponseStatus: 200, ResponseHeaders: map[string]string{"content-type": "text/html"}},
	}
	doc := map[string]any{
		"paths": map[string]any{
			"/api/v1/users": map[string]any{"get": map[string]any{}},
		},
	}

	report := BuildCoverage(apiFlows, doc)

	if report.Represented != 1 {
		t.Fatalf("Represented = %d, want 1", report.Represented)
	}
	if got := report.ExcludedCount(); got != 1 {
		t.Fatalf("ExcludedCount = %d, want 1", got)
	}
	ex := report.Excluded[0]
	if ex.Path != "/bin/list" || ex.Method != "GET" || ex.ContentType != "text/html" {
		t.Fatalf("excluded = %+v", ex)
	}
	if ex.Reason == "" {
		t.Fatal("excluded reason is empty")
	}
}

func TestBuildCoverageDedupesRepeatedExcludedCalls(t *testing.T) {
	apiFlows := []model.CapturedFlow{
		{Method: "GET", Host: "example.com", Path: "/bin/list?pageOffset=0", ResponseStatus: 200, ResponseHeaders: map[string]string{"content-type": "text/html"}},
		{Method: "GET", Host: "example.com", Path: "/bin/list?pageOffset=48", ResponseStatus: 200, ResponseHeaders: map[string]string{"content-type": "text/html"}},
	}
	report := BuildCoverage(apiFlows, map[string]any{"paths": map[string]any{}})
	if report.ExcludedCount() != 1 {
		t.Fatalf("ExcludedCount = %d, want 1 (same host, normalized path+method)", report.ExcludedCount())
	}
}

func TestBuildCoverageKeepsCrossHostExcludedDistinct(t *testing.T) {
	apiFlows := []model.CapturedFlow{
		{Method: "GET", Host: "example.com", Path: "/bin/list", ResponseStatus: 0, ResponseHeaders: map[string]string{"content-type": "text/html"}},
		{Method: "GET", Host: "partner.test", Path: "/bin/list", ResponseStatus: 0, ResponseHeaders: map[string]string{"content-type": "text/html"}},
	}
	report := BuildCoverage(apiFlows, map[string]any{"paths": map[string]any{}})
	if report.ExcludedCount() != 2 {
		t.Fatalf("ExcludedCount = %d, want 2 (distinct hosts)", report.ExcludedCount())
	}
}

func TestExcludedReasonMirrorsGenerateSkipPredicates(t *testing.T) {
	apiFlows := []model.CapturedFlow{
		{Method: "CONNECT", Host: "example.com", Path: "/tunnel", ResponseStatus: 200},
	}
	report := BuildCoverage(apiFlows, map[string]any{"paths": map[string]any{}})
	if report.ExcludedCount() != 1 {
		t.Fatalf("ExcludedCount = %d, want 1", report.ExcludedCount())
	}
	if !strings.Contains(report.Excluded[0].Reason, "OpenAPI operation") {
		t.Fatalf("reason = %q, want it to name the unsupported method", report.Excluded[0].Reason)
	}
}

func TestExcludedContentTypesBreakdown(t *testing.T) {
	report := CoverageReport{Excluded: []ExcludedFlow{
		{ContentType: "text/html"},
		{ContentType: "text/html"},
		{ContentType: ""},
	}}
	got := report.ExcludedContentTypes()
	if got["text/html"] != 2 || got["unknown"] != 1 {
		t.Fatalf("breakdown = %#v", got)
	}
}

func TestGeneratedHTMLEndpointIsRepresentedNotExcluded(t *testing.T) {
	flow := model.CapturedFlow{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/bin/list",
		URL:             "https://example.com/bin/list",
		RequestHeaders:  map[string]string{"sec-fetch-dest": "empty", "sec-fetch-mode": "cors"},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "text/html"},
		ResponseBody:    []byte("<li class=tile></li>"),
	}
	pipeline, err := BuildPipeline([]model.CapturedFlow{flow}, "example.com", InclusionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	doc := mustGenerate(t, pipeline.APIFlows, "example.com", pipeline.Auth, Options{})
	report := BuildCoverage(pipeline.APIFlows, doc)
	if report.ExcludedCount() != 0 {
		t.Fatalf("ExcludedCount = %d, want 0; excluded = %+v", report.ExcludedCount(), report.Excluded)
	}
	if report.Represented != 1 {
		t.Fatalf("Represented = %d, want 1", report.Represented)
	}
}

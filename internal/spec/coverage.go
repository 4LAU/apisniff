package spec

import (
	"fmt"
	"sort"
	"strings"

	"github.com/4LAU/apisniff/internal/model"
)

// CoverageReport reconciles the API-candidate flows handed to Generate against
// the emitted spec. Every candidate is either represented as an operation or
// listed in Excluded with a reason — the spec can never silently omit a
// captured candidate endpoint.
type CoverageReport struct {
	Represented int            `json:"represented"`
	Excluded    []ExcludedFlow `json:"excluded"`
}

// ExcludedFlow is an API-candidate flow that did not become an operation.
type ExcludedFlow struct {
	Method      string `json:"method"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	ContentType string `json:"content_type,omitempty"`
	Reason      string `json:"reason"`
}

func (r CoverageReport) ExcludedCount() int { return len(r.Excluded) }

// ExcludedContentTypes counts excluded flows by content-type for a one-line
// summary. An empty content-type is reported as "unknown".
func (r CoverageReport) ExcludedContentTypes() map[string]int {
	out := map[string]int{}
	for _, e := range r.Excluded {
		ct := e.ContentType
		if ct == "" {
			ct = "unknown"
		}
		out[ct]++
	}
	return out
}

// BuildCoverage diffs the API-candidate flows (the exact set handed to Generate,
// i.e. pipeline.APIFlows) against the operations emitted in doc. Passing the
// generator's real input is what keeps the report correct: ordinary HTML page
// navigations are filtered out before they reach here, and inclusion-filter
// flows (classified drop but selected for the spec) are included. Excluded
// entries are deduped by normalized (method, host, path) and sorted.
func BuildCoverage(apiFlows []model.CapturedFlow, doc map[string]any) CoverageReport {
	emitted := emittedOperations(doc)
	report := CoverageReport{}
	seen := map[string]struct{}{}
	for _, f := range apiFlows {
		method := strings.ToLower(f.Method)
		normPath, _, ok := model.NormalizeSpecPath(f.Path)
		if ok && isOpenAPIOperation(method) {
			if _, in := emitted[normPath+"\x00"+method]; in {
				report.Represented++
				continue
			}
		}
		displayPath := normPath
		if !ok {
			displayPath = strings.SplitN(f.Path, "?", 2)[0]
		}
		dedupeKey := method + "\x00" + normalizeHost(f.Host) + "\x00" + displayPath
		if _, dup := seen[dedupeKey]; dup {
			continue
		}
		seen[dedupeKey] = struct{}{}
		report.Excluded = append(report.Excluded, ExcludedFlow{
			Method:      strings.ToUpper(f.Method),
			Host:        f.Host,
			Path:        displayPath,
			ContentType: f.ContentType(),
			Reason:      exclusionReason(f),
		})
	}
	sort.Slice(report.Excluded, func(i, j int) bool {
		if report.Excluded[i].Path == report.Excluded[j].Path {
			return report.Excluded[i].Method < report.Excluded[j].Method
		}
		return report.Excluded[i].Path < report.Excluded[j].Path
	})
	return report
}

// emittedOperations returns the set of "path\x00method" present in the doc.
func emittedOperations(doc map[string]any) map[string]struct{} {
	out := map[string]struct{}{}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		return out
	}
	for path, rawItem := range paths {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		for method := range item {
			lower := strings.ToLower(method)
			if isOpenAPIOperation(lower) {
				out[path+"\x00"+lower] = struct{}{}
			}
		}
	}
	return out
}

// exclusionReason mirrors Generate's skip predicates (aggregateOperations) so
// each excluded candidate gets an accurate reason. Order MUST match Generate:
// status range, then OpenAPI method, then path normalization; the
// content-type/no-schema line is the defensive fallback.
func exclusionReason(f model.CapturedFlow) string {
	if f.ResponseStatus < 100 || f.ResponseStatus > 599 {
		return fmt.Sprintf("response status %d is outside 100-599; not a documentable operation", f.ResponseStatus)
	}
	if !isOpenAPIOperation(strings.ToLower(f.Method)) {
		return "method " + f.Method + " is not an OpenAPI operation"
	}
	if _, _, ok := model.NormalizeSpecPath(f.Path); !ok {
		return "path could not be normalized to an OpenAPI template"
	}
	ct := f.ContentType()
	if ct == "" {
		ct = "no content-type"
	}
	return ct + " response; no schema could be inferred"
}

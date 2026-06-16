package output

import (
	"fmt"
	"strings"

	"github.com/4LAU/apisniff/internal/model"
)

func WriteProbe(cfg Config, assessment *model.ProbeAssessment) error {
	if assessment == nil {
		return fmt.Errorf("probe assessment is nil")
	}
	s := newStyles(cfg)
	lines := []string{
		s.headerBox("apisniff probe", assessment.URL),
		"",
		"  " + s.verdictBadge(assessment.Verdict.String()),
	}
	if len(assessment.Vendors) > 0 {
		var names []string
		for _, match := range assessment.Vendors {
			names = append(names, match.Vendor+" ("+match.Confidence+")")
		}
		lines = append(lines, s.kv("vendor", strings.Join(names, ", ")))
	}
	if assessment.GraphQL != nil && (assessment.GraphQL.Introspection || len(assessment.GraphQL.Endpoints) > 0) {
		lines = append(lines, s.kv("graphql", graphqlSummary(assessment.GraphQL)))
	}
	if assessment.RateLimit != nil {
		lines = append(lines, s.kv("rate limit", rateLimitSummary(assessment.RateLimit)))
	}
	rows := make([]probeRow, 0, len(assessment.Results))
	for _, result := range assessment.Results {
		rows = append(rows, probeRow{
			Variant:   result.Variant,
			Status:    result.Status,
			LatencyMS: result.ElapsedMS(),
			Blocked:   result.IsBlocked(),
			Challenge: result.IsChallenge(),
			Error:     result.Error,
		})
	}
	if len(rows) > 0 {
		lines = append(lines, "", s.probeTable(rows))
	}
	if assessment.Recommendation != "" {
		lines = append(lines, "", s.panel("Recommendation", assessment.Recommendation))
	}
	return s.writeLines(lines...)
}

func graphqlSummary(result *model.GraphQLResult) string {
	status := "introspection=false"
	if result.Introspection {
		status = "introspection=true"
	}
	if len(result.Endpoints) == 0 {
		return status + ", endpoints=0"
	}
	return fmt.Sprintf("%s, endpoints=%d (%s)", status, len(result.Endpoints), strings.Join(result.Endpoints, ", "))
}

func rateLimitSummary(result *model.RateLimitResult) string {
	var parts []string
	if result.FirstBlockAt > 0 {
		parts = append(parts, fmt.Sprintf("blocked after %d of %d requests (%d)",
			result.FirstBlockAt, result.RequestsSent, result.BlockStatus))
	} else {
		parts = append(parts, fmt.Sprintf("%d requests, no block", result.RequestsSent))
	}
	if result.RetryAfter != "" {
		parts = append(parts, "retry-after "+result.RetryAfter+"s")
	}
	parts = append(parts, fmt.Sprintf("median %.1fms", result.MedianMS))
	if result.SilentThrottle {
		parts = append(parts, "silent throttle detected")
	}
	return strings.Join(parts, ", ")
}

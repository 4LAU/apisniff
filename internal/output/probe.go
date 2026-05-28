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
		s.title("apisniff probe"),
		s.summary("url", assessment.URL),
		s.summary("verdict", s.verdictBadge(assessment.Verdict.String())),
	}
	if len(assessment.Vendors) > 0 {
		var names []string
		for _, match := range assessment.Vendors {
			names = append(names, match.Vendor+"("+match.Confidence+")")
		}
		lines = append(lines, s.summary("vendors", strings.Join(names, ", ")))
	}
	if assessment.GraphQL != nil {
		lines = append(lines, s.summary("graphql", graphqlSummary(assessment.GraphQL)))
	}
	if assessment.RateLimit != nil {
		lines = append(lines, s.summary("rate limit", rateLimitSummary(assessment.RateLimit)))
	}
	lines = append(lines, "", s.header("Probe variants"))
	for _, result := range assessment.Results {
		status := fmt.Sprint(result.Status)
		if result.Status == 0 {
			status = "-"
		}
		detail := fmt.Sprintf(
			"elapsed=%.1fms blocked=%t challenge=%t",
			result.ElapsedMS(),
			result.IsBlocked(),
			result.IsChallenge(),
		)
		if result.Error != "" {
			detail += " error=" + result.Error
		}
		lines = append(lines, s.row(result.Variant, s.statusBadge(status), detail))
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
	parts := []string{fmt.Sprintf("requests=%d", result.RequestsSent)}
	if result.FirstBlockAt > 0 {
		parts = append(parts, fmt.Sprintf("first_block_at=%d", result.FirstBlockAt))
	}
	if result.BlockStatus > 0 {
		parts = append(parts, fmt.Sprintf("block_status=%d", result.BlockStatus))
	}
	if result.RetryAfter != "" {
		parts = append(parts, "retry_after="+result.RetryAfter)
	}
	parts = append(parts, fmt.Sprintf("median=%.1fms", result.MedianMS))
	if result.SilentThrottle {
		parts = append(parts, "silent_throttle=true")
	}
	return strings.Join(parts, ", ")
}

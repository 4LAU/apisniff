package output

import (
	"fmt"

	"github.com/4LAU/apisniff-go/internal/auth"
	"github.com/4LAU/apisniff-go/internal/model"
)

type AnalyzeResult struct {
	SchemaVersion int                    `json:"schema_version"`
	Domain        string                 `json:"domain,omitempty"`
	BundleDir     string                 `json:"bundle_dir,omitempty"`
	TotalFlows    int                    `json:"total_flows"`
	TopEndpoints  []EndpointSummary      `json:"top_endpoints"`
	AuthPatterns  []auth.Pattern         `json:"auth_patterns,omitempty"`
	Cookies       []auth.ExtractedCookie `json:"cookies,omitempty"`
	Flows         []model.CapturedFlow   `json:"flows,omitempty"`
}

type EndpointSummary struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Count  int    `json:"count"`
}

func WriteAnalyze(cfg Config, result AnalyzeResult) error {
	s := newStyles(cfg)
	lines := []string{s.title("apisniff analyze")}
	if result.Domain != "" {
		lines = append(lines, s.summary("domain", result.Domain))
	}
	lines = append(lines,
		s.summary("flows", fmt.Sprintf("%d", result.TotalFlows)),
		s.summary("top endpoints", fmt.Sprintf("%d", len(result.TopEndpoints))),
		s.summary("auth patterns", fmt.Sprintf("%d", len(result.AuthPatterns))),
		s.summary("cookies", fmt.Sprintf("%d", len(result.Cookies))),
	)
	if result.BundleDir != "" {
		lines = append(lines, s.summary("bundle", result.BundleDir))
	}
	lines = append(lines, "", s.header("Top endpoints"))
	if len(result.TopEndpoints) == 0 {
		lines = append(lines, s.empty("none"))
	} else {
		for _, endpoint := range result.TopEndpoints {
			lines = append(lines, s.row(
				s.methodBadge(endpoint.Method),
				endpoint.Path,
				fmt.Sprintf("%d", endpoint.Count),
			))
		}
	}
	if len(result.AuthPatterns) > 0 {
		lines = append(lines, "", s.header("Auth patterns"))
		for _, pattern := range result.AuthPatterns {
			lines = append(lines, s.row(
				pattern.AuthType,
				pattern.Detail,
				fmt.Sprintf("%d flows", pattern.FlowCount),
			))
		}
	}
	if len(result.Cookies) > 0 {
		lines = append(lines, "", s.header("Cookies"))
		for _, cookie := range result.Cookies {
			lines = append(lines, s.row(cookie.Name, cookie.Domain+cookie.Path, cookie.Source))
		}
	}
	return s.writeLines(lines...)
}

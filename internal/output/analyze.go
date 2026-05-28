package output

import (
	"fmt"
	"strings"

	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/model"
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
	lines := []string{
		s.headerBox("apisniff analyze", result.Domain),
		"",
		analyzeSummary(s, result),
	}
	if result.BundleDir != "" {
		lines = append(lines, s.kv("bundle", s.faint(result.BundleDir)))
	}
	if len(result.TopEndpoints) > 0 {
		rows := make([][]string, 0, len(result.TopEndpoints))
		for _, endpoint := range result.TopEndpoints {
			rows = append(rows, []string{
				s.methodBadge(endpoint.Method),
				endpoint.Path,
				fmt.Sprintf("%d", endpoint.Count),
			})
		}
		lines = append(lines, "", s.section("Top endpoints"), s.simpleTable([]string{"Method", "Path", "Count"}, rows))
	}
	if len(result.AuthPatterns) > 0 {
		rows := make([][]string, 0, len(result.AuthPatterns))
		for _, pattern := range result.AuthPatterns {
			rows = append(rows, []string{
				pattern.AuthType,
				pattern.Detail,
				fmt.Sprintf("%d", pattern.FlowCount),
			})
		}
		lines = append(lines, "", s.section("Auth patterns"), s.simpleTable([]string{"Type", "Detail", "Flows"}, rows))
	}
	if len(result.Cookies) > 0 {
		rows := make([][]string, 0, len(result.Cookies))
		for _, cookie := range result.Cookies {
			rows = append(rows, []string{
				cookie.Name,
				cookie.Domain + cookie.Path,
				cookie.Source,
			})
		}
		lines = append(lines, "", s.section("Cookies"), s.simpleTable([]string{"Name", "Domain", "Source"}, rows))
	}
	return s.writeLines(lines...)
}

func analyzeSummary(s styles, result AnalyzeResult) string {
	if s.cfg.Width < 60 {
		return strings.Join([]string{
			s.kv("flows", fmt.Sprintf("%d", result.TotalFlows)),
			s.kv("endpoints", fmt.Sprintf("%d", len(result.TopEndpoints))),
			s.kv("auth types", fmt.Sprintf("%d", len(result.AuthPatterns))),
			s.kv("cookies", fmt.Sprintf("%d", len(result.Cookies))),
		}, "\n")
	}
	parts := []string{
		compactKV(s, "flows", fmt.Sprintf("%d", result.TotalFlows)),
		compactKV(s, "endpoints", fmt.Sprintf("%d", len(result.TopEndpoints))),
		compactKV(s, "auth types", fmt.Sprintf("%d", len(result.AuthPatterns))),
		compactKV(s, "cookies", fmt.Sprintf("%d", len(result.Cookies))),
	}
	return "  " + strings.Join(parts, "    ")
}

func compactKV(s styles, label, value string) string {
	return s.faint(label) + " " + value
}

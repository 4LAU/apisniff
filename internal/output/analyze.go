package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/4LAU/apisniff-go/internal/auth"
	"github.com/4LAU/apisniff-go/internal/model"
)

type AnalyzeResult struct {
	SchemaVersion int                    `json:"schema_version"`
	Domain        string                 `json:"domain,omitempty"`
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

func WriteAnalyze(w io.Writer, result AnalyzeResult, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Fprintf(w, "analyzed %d flows\n", result.TotalFlows)
	for _, endpoint := range result.TopEndpoints {
		fmt.Fprintf(w, "  %-7s %-40s %d\n", endpoint.Method, endpoint.Path, endpoint.Count)
	}
	return nil
}

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/4LAU/apisniff-go/internal/model"
)

type probeJSON struct {
	SchemaVersion  int                    `json:"schema_version"`
	URL            string                 `json:"url"`
	Verdict        string                 `json:"verdict"`
	Recommendation string                 `json:"recommendation"`
	Probes         []probeResultJSON      `json:"probes"`
	Vendors        []model.VendorMatch    `json:"vendors"`
	GraphQL        *model.GraphQLResult   `json:"graphql,omitempty"`
	RateLimit      *model.RateLimitResult `json:"rate_limit,omitempty"`
}

type probeResultJSON struct {
	Variant   string  `json:"variant"`
	Status    int     `json:"status,omitempty"`
	ElapsedMS float64 `json:"elapsed_ms"`
	Blocked   bool    `json:"blocked"`
	Challenge bool    `json:"challenge"`
	Error     string  `json:"error,omitempty"`
}

func WriteProbe(w io.Writer, assessment *model.ProbeAssessment, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(probeToJSON(assessment))
	}
	fmt.Fprintf(w, "apisniff probe %s\n", assessment.URL)
	fmt.Fprintf(w, "verdict: %s\n", assessment.Verdict.String())
	if len(assessment.Vendors) > 0 {
		var names []string
		for _, match := range assessment.Vendors {
			names = append(names, match.Vendor+"("+match.Confidence+")")
		}
		fmt.Fprintf(w, "vendors: %s\n", strings.Join(names, ", "))
	}
	for _, result := range assessment.Results {
		status := fmt.Sprint(result.Status)
		if result.Status == 0 {
			status = "-"
		}
		fmt.Fprintf(w, "  %-12s status=%s elapsed=%.1fms blocked=%t challenge=%t",
			result.Variant, status, result.ElapsedMS(), result.IsBlocked(), result.IsChallenge())
		if result.Error != "" {
			fmt.Fprintf(w, " error=%s", result.Error)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "recommendation: %s\n", assessment.Recommendation)
	return nil
}

func probeToJSON(assessment *model.ProbeAssessment) probeJSON {
	probes := make([]probeResultJSON, 0, len(assessment.Results))
	for _, result := range assessment.Results {
		probes = append(probes, probeResultJSON{
			Variant:   result.Variant,
			Status:    result.Status,
			ElapsedMS: result.ElapsedMS(),
			Blocked:   result.IsBlocked(),
			Challenge: result.IsChallenge(),
			Error:     result.Error,
		})
	}
	return probeJSON{
		SchemaVersion:  1,
		URL:            assessment.URL,
		Verdict:        assessment.Verdict.String(),
		Recommendation: assessment.Recommendation,
		Probes:         probes,
		Vendors:        assessment.Vendors,
		GraphQL:        assessment.GraphQL,
		RateLimit:      assessment.RateLimit,
	}
}

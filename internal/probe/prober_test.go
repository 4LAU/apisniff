package probe

import (
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func TestClassifyAllConnectionErrorsIsNotNoProtection(t *testing.T) {
	results := []model.ProbeResult{
		{Variant: "naked", Error: "dial tcp: no such host"},
		{Variant: "impersonated", Error: "dial tcp: no such host"},
		{Variant: "tls_only", Error: "dial tcp: no such host"},
	}
	verdict, recommendation := Classify(results, nil)
	if verdict == model.NoProtection || !strings.Contains(recommendation, "network errors") {
		t.Fatalf("verdict=%s recommendation=%q", verdict, recommendation)
	}
}

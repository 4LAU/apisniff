package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func TestWriteReconDefensesPanel(t *testing.T) {
	t.Run("two vendors including underscore id", func(t *testing.T) {
		var buf bytes.Buffer
		result := ReconResult{
			Domain:    "example.com",
			BundleDir: "/tmp/bundle",
			FlowsPath: "/tmp/bundle/flows.jsonl",
			KeptFlows: 10,
			Defenses: []model.VendorMatch{
				{
					Vendor:     "akamai",
					Confidence: "high",
					Signals:    []string{"high:cookie:_abck", "high:body:bmak."},
				},
				{
					Vendor:     "shape_security",
					Confidence: "medium",
					Signals:    []string{"medium:header:x-shape-challenge"},
				},
			},
		}
		if err := WriteRecon(testConfig(t, &buf), result); err != nil {
			t.Fatalf("WriteRecon: %v", err)
		}
		out := buf.String()

		if !strings.Contains(out, "Defenses observed") {
			t.Fatalf("output missing 'Defenses observed' panel:\n%s", out)
		}
		// Underscore in vendor id replaced with space
		if !strings.Contains(out, "shape security") {
			t.Fatalf("output missing 'shape security' (underscore → space):\n%s", out)
		}
		if strings.Contains(out, "shape_security") {
			t.Fatalf("output contains raw 'shape_security', expected space-replaced form:\n%s", out)
		}
		// Confidence shown in parens
		if !strings.Contains(out, "akamai (high)") {
			t.Fatalf("output missing 'akamai (high)':\n%s", out)
		}
		if !strings.Contains(out, "shape security (medium)") {
			t.Fatalf("output missing 'shape security (medium)':\n%s", out)
		}
		// Signal rest shown WITHOUT confidence:type: prefix
		if !strings.Contains(out, "_abck") {
			t.Fatalf("output missing signal rest '_abck':\n%s", out)
		}
		if strings.Contains(out, "high:cookie:_abck") {
			t.Fatalf("output contains raw signal label 'high:cookie:_abck', prefix should be stripped:\n%s", out)
		}
		if !strings.Contains(out, "bmak.") {
			t.Fatalf("output missing signal rest 'bmak.':\n%s", out)
		}
		if !strings.Contains(out, "x-shape-challenge") {
			t.Fatalf("output missing signal rest 'x-shape-challenge':\n%s", out)
		}
	})

	t.Run("signal rest contains colon — SplitN not last-colon", func(t *testing.T) {
		var buf bytes.Buffer
		result := ReconResult{
			Domain:    "example.com",
			BundleDir: "/tmp/bundle",
			FlowsPath: "/tmp/bundle/flows.jsonl",
			KeptFlows: 5,
			Defenses: []model.VendorMatch{
				{
					Vendor:     "test_vendor",
					Confidence: "high",
					Signals:    []string{"high:body:a:b:c"},
				},
			},
		}
		if err := WriteRecon(testConfig(t, &buf), result); err != nil {
			t.Fatalf("WriteRecon: %v", err)
		}
		out := buf.String()

		// Full rest "a:b:c" must appear (3-part split takes everything after 2nd colon)
		if !strings.Contains(out, "a:b:c") {
			t.Fatalf("output missing full rest 'a:b:c':\n%s", out)
		}
		// Must NOT be truncated to just "c" (last-colon behaviour)
		if strings.Contains(out, " c\n") || strings.Contains(out, " c)") {
			t.Fatalf("output appears to show only last-colon remainder 'c' instead of 'a:b:c':\n%s", out)
		}
	})

	t.Run("unattributed only", func(t *testing.T) {
		var buf bytes.Buffer
		result := ReconResult{
			Domain:              "example.com",
			BundleDir:           "/tmp/bundle",
			FlowsPath:           "/tmp/bundle/flows.jsonl",
			KeptFlows:           7,
			UnattributedAntibot: 3,
		}
		if err := WriteRecon(testConfig(t, &buf), result); err != nil {
			t.Fatalf("WriteRecon: %v", err)
		}
		out := buf.String()

		if !strings.Contains(out, "Defenses observed") {
			t.Fatalf("output missing 'Defenses observed' panel:\n%s", out)
		}
		if !strings.Contains(out, "unattributed antibot (3 flows)") {
			t.Fatalf("output missing 'unattributed antibot (3 flows)':\n%s", out)
		}
	})

	t.Run("vendor with no signals omits dangling separator", func(t *testing.T) {
		var buf bytes.Buffer
		result := ReconResult{
			Domain:    "example.com",
			BundleDir: "/tmp/bundle",
			FlowsPath: "/tmp/bundle/flows.jsonl",
			KeptFlows: 5,
			Defenses: []model.VendorMatch{
				{Vendor: "akamai", Confidence: "high"},
			},
		}
		if err := WriteRecon(testConfig(t, &buf), result); err != nil {
			t.Fatalf("WriteRecon: %v", err)
		}
		out := buf.String()

		if !strings.Contains(out, "akamai (high)") {
			t.Fatalf("output missing 'akamai (high)':\n%s", out)
		}
		// No signals → no trailing em-dash separator
		if strings.Contains(out, "—") {
			t.Fatalf("output has a dangling '—' separator for a vendor with no signals:\n%s", out)
		}
	})

	t.Run("no defenses no panel", func(t *testing.T) {
		var buf bytes.Buffer
		result := ReconResult{
			Domain:    "example.com",
			BundleDir: "/tmp/bundle",
			FlowsPath: "/tmp/bundle/flows.jsonl",
			KeptFlows: 4,
		}
		if err := WriteRecon(testConfig(t, &buf), result); err != nil {
			t.Fatalf("WriteRecon: %v", err)
		}
		out := buf.String()

		if strings.Contains(out, "Defenses observed") {
			t.Fatalf("output unexpectedly contains 'Defenses observed' when no defenses present:\n%s", out)
		}
	})
}

func TestWriteReconShowsDuration(t *testing.T) {
	var buf bytes.Buffer
	result := ReconResult{
		Domain:          "example.com",
		BundleDir:       "/tmp/bundle",
		FlowsPath:       "/tmp/bundle/flows.jsonl",
		KeptFlows:       42,
		DurationSeconds: 8.3,
	}
	if err := WriteRecon(testConfig(t, &buf), result); err != nil {
		t.Fatalf("WriteRecon: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "42 flows") {
		t.Fatalf("output missing flow count:\n%s", out)
	}
	if !strings.Contains(out, "in 8.3s") {
		t.Fatalf("output missing duration:\n%s", out)
	}
}

func TestWriteReconNoDurationWhenZero(t *testing.T) {
	var buf bytes.Buffer
	result := ReconResult{
		Domain:    "example.com",
		BundleDir: "/tmp/bundle",
		FlowsPath: "/tmp/bundle/flows.jsonl",
		KeptFlows: 10,
	}
	if err := WriteRecon(testConfig(t, &buf), result); err != nil {
		t.Fatalf("WriteRecon: %v", err)
	}
	if strings.Contains(buf.String(), "in 0") {
		t.Fatalf("output shows duration when zero:\n%s", buf.String())
	}
}

func TestWriteSpecStatusMethodBreakdown(t *testing.T) {
	var buf bytes.Buffer
	result := SpecStatusResult{
		Domain:     "example.com",
		Format:     "yaml",
		OutputPath: "/tmp/spec.yaml",
		Paths:      14,
		Operations: 23,
		MethodCounts: map[string]int{
			"GET": 12, "POST": 6, "PUT": 3, "DELETE": 2,
		},
	}
	if err := WriteSpecStatus(testConfig(t, &buf), result); err != nil {
		t.Fatalf("WriteSpecStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "14 paths") {
		t.Fatalf("output missing paths count:\n%s", out)
	}
	if !strings.Contains(out, "23 operations") {
		t.Fatalf("output missing operations count:\n%s", out)
	}
	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		if !strings.Contains(out, "["+method+"]") {
			t.Fatalf("output missing method badge for %s:\n%s", method, out)
		}
	}
}

func TestWriteSpecStatusPrintsExcludedCoverage(t *testing.T) {
	var buf bytes.Buffer
	result := SpecStatusResult{
		Domain:               "example.com",
		Paths:                2,
		Operations:           3,
		ExcludedCount:        2,
		ExcludedContentTypes: map[string]int{"text/html": 2},
	}
	if err := WriteSpecStatus(testConfig(t, &buf), result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "2 captured endpoint") || !strings.Contains(out, "text/html") {
		t.Fatalf("coverage warning missing from output:\n%s", out)
	}
}

func TestWriteSpecStatusGraphQL(t *testing.T) {
	var buf bytes.Buffer
	result := SpecStatusResult{
		Domain:            "example.com",
		Format:            "yaml",
		OutputPath:        "/tmp/spec.yaml",
		Paths:             3,
		Operations:        5,
		GraphQLOperations: 8,
		GraphQLFlows:      2,
	}
	if err := WriteSpecStatus(testConfig(t, &buf), result); err != nil {
		t.Fatalf("WriteSpecStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "GraphQL") {
		t.Fatalf("output missing GraphQL section:\n%s", out)
	}
	if !strings.Contains(out, "8 operations") {
		t.Fatalf("output missing GraphQL operation count:\n%s", out)
	}
}

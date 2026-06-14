package capture

import (
	"reflect"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/vendor"
)

func newTestDetector(t *testing.T) *vendor.Detector {
	t.Helper()
	det, err := vendor.NewDetector()
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return det
}

func vendorNames(matches []model.VendorMatch) []string {
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.Vendor
	}
	return out
}

// 1 + 2: scoping by HostRole.
func TestDetectDefensesScoping(t *testing.T) {
	det := newTestDetector(t)
	akamaiFlow := model.CapturedFlow{
		Host:            "shop.example.com",
		ResponseHeaders: map[string]string{"set-cookie": "_abck=ABC; Path=/"},
		ResponseStatus:  200,
	}

	t.Run("target host matches akamai", func(t *testing.T) {
		matches, scoped := detectDefenses(det, "example.com", akamaiFlow, model.ClassifyResult{HostRole: "target"})
		if !scoped {
			t.Fatal("expected scoped=true for target")
		}
		if got := vendorNames(matches); !reflect.DeepEqual(got, []string{"akamai"}) {
			t.Fatalf("vendors = %v, want [akamai]", got)
		}
	})

	t.Run("third_party out of scope", func(t *testing.T) {
		matches, scoped := detectDefenses(det, "example.com", akamaiFlow, model.ClassifyResult{HostRole: "third_party"})
		if scoped || matches != nil {
			t.Fatalf("expected out of scope, got scoped=%v matches=%v", scoped, matches)
		}
	})

	t.Run("same_site out of scope", func(t *testing.T) {
		matches, scoped := detectDefenses(det, "example.com", akamaiFlow, model.ClassifyResult{HostRole: "same_site"})
		if scoped || matches != nil {
			t.Fatalf("expected out of scope, got scoped=%v matches=%v", scoped, matches)
		}
	})
}

// 3: empty HostRole falls back to registered-domain match.
func TestDetectDefensesEmptyHostRoleFallback(t *testing.T) {
	det := newTestDetector(t)
	resp := map[string]string{"set-cookie": "datadome=XYZ; Path=/"}

	cases := []struct {
		name   string
		host   string
		result model.ClassifyResult
		want   bool
	}{
		{"OPTIONS preflight on target", "api.example.com", model.ClassifyResult{Category: model.Options}, true},
		{"path_telemetry on target", "example.com", model.ClassifyResult{Category: model.Telemetry, Reason: "path_telemetry"}, true},
		{"third-party host empty role", "vendor.other.com", model.ClassifyResult{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flow := model.CapturedFlow{Host: tc.host, ResponseHeaders: resp, ResponseStatus: 200}
			matches, scoped := detectDefenses(det, "example.com", flow, tc.result)
			if scoped != tc.want {
				t.Fatalf("scoped = %v, want %v", scoped, tc.want)
			}
			if tc.want {
				if got := vendorNames(matches); !reflect.DeepEqual(got, []string{"datadome"}) {
					t.Fatalf("vendors = %v, want [datadome]", got)
				}
			} else if matches != nil {
				t.Fatalf("expected no matches, got %v", matches)
			}
		})
	}
}

// 4: infra false-positive guard.
func TestDetectDefensesInfraGuard(t *testing.T) {
	det := newTestDetector(t)
	target := model.ClassifyResult{HostRole: "target"}
	host := "www.example.com"

	mustEmpty := func(t *testing.T, headers map[string]string) {
		t.Helper()
		flow := model.CapturedFlow{Host: host, ResponseHeaders: headers, ResponseStatus: 200}
		matches, scoped := detectDefenses(det, "example.com", flow, target)
		if !scoped {
			t.Fatal("expected scoped=true")
		}
		if len(matches) != 0 {
			t.Fatalf("expected no defense matches, got %v", matches)
		}
	}

	t.Run("cf-ray only", func(t *testing.T) {
		mustEmpty(t, map[string]string{"cf-ray": "abc-LAX"})
	})
	t.Run("x-amzn-requestid only", func(t *testing.T) {
		mustEmpty(t, map[string]string{"x-amzn-requestid": "req-123"})
	})
	t.Run("BIGipServer cookie only", func(t *testing.T) {
		mustEmpty(t, map[string]string{"set-cookie": "BIGipServerpool=12345; Path=/"})
	})
	t.Run("x-cache cloudfront error only", func(t *testing.T) {
		mustEmpty(t, map[string]string{"x-cache": "Error from cloudfront"})
	})

	t.Run("cf-ray plus cf_clearance -> cloudflare medium not inflated", func(t *testing.T) {
		flow := model.CapturedFlow{
			Host:            host,
			ResponseHeaders: map[string]string{"cf-ray": "abc-LAX", "set-cookie": "cf_clearance=tok; Path=/"},
			ResponseStatus:  200,
		}
		matches, scoped := detectDefenses(det, "example.com", flow, target)
		if !scoped {
			t.Fatal("expected scoped=true")
		}
		if len(matches) != 1 || matches[0].Vendor != "cloudflare" {
			t.Fatalf("matches = %v, want single cloudflare", matches)
		}
		if matches[0].Confidence != "medium" {
			t.Fatalf("confidence = %q, want medium (cf_clearance cookie, not inflated by cf-ray)", matches[0].Confidence)
		}
		if !reflect.DeepEqual(matches[0].Signals, []string{"medium:cookie:cf_clearance"}) {
			t.Fatalf("signals = %v, want only the cookie", matches[0].Signals)
		}
	})
}

// 5: completeness — every emittable label is classified, and the predicate
// agrees with the two sets.
func TestDefenseSignalCompleteness(t *testing.T) {
	det := newTestDetector(t)
	for _, label := range det.Labels() {
		// classify by the same confidence-stripped key the predicate uses.
		stripped := stripConfidence(label)
		inDefense := defenseSignals[stripped]
		inInfra := infraSignals[stripped]
		if !inDefense && !inInfra {
			t.Errorf("label %q (key %q) is unclassified: add it to defenseSignals or infraSignals", label, stripped)
			continue
		}
		if inDefense && inInfra {
			t.Errorf("key %q is in BOTH defenseSignals and infraSignals", stripped)
		}
		if got := defenseSignalAllowed(label); got != inDefense {
			t.Errorf("defenseSignalAllowed(%q) = %v, want %v", label, got, inDefense)
		}
	}
}

func stripConfidence(label string) string {
	for i := 0; i < len(label); i++ {
		if label[i] == ':' {
			return label[i+1:]
		}
	}
	return label
}

// 6: dedupe / best confidence and sort.
func TestMergeAndSortedDefenses(t *testing.T) {
	acc := map[string]model.VendorMatch{}
	mergeDefenses(acc, []model.VendorMatch{
		{Vendor: "akamai", Confidence: "low", Signals: []string{"low:cookie:bm_sz"}},
		{Vendor: "datadome", Confidence: "high", Signals: []string{"high:cookie:datadome"}},
	})
	mergeDefenses(acc, []model.VendorMatch{
		{Vendor: "akamai", Confidence: "high", Signals: []string{"high:cookie:_abck"}},
	})

	got := sortedDefenses(acc)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Vendor != "akamai" || got[1].Vendor != "datadome" {
		t.Fatalf("order = %v, want [akamai datadome]", vendorNames(got))
	}
	if got[0].Confidence != "high" {
		t.Fatalf("akamai confidence = %q, want high (kept best)", got[0].Confidence)
	}
}

// 7: nil detector.
func TestDetectDefensesNilDetector(t *testing.T) {
	matches, scoped := detectDefenses(nil, "example.com",
		model.CapturedFlow{Host: "example.com"}, model.ClassifyResult{HostRole: "target"})
	if scoped || matches != nil {
		t.Fatalf("nil detector: got scoped=%v matches=%v, want false nil", scoped, matches)
	}
}

// 8: isAntibot.
func TestIsAntibot(t *testing.T) {
	if !isAntibot(model.ClassifyResult{Category: model.Antibot}) {
		t.Error("Antibot category should be antibot")
	}
	if !isAntibot(model.ClassifyResult{Category: model.Static, Signals: []string{"antibot_js"}}) {
		t.Error("antibot_js signal should be antibot")
	}
	if isAntibot(model.ClassifyResult{Category: model.Static}) {
		t.Error("plain static should not be antibot")
	}
}

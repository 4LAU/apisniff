package vendor

import "testing"

func TestDetectorMatchesCloudflare(t *testing.T) {
	detector := MustDetector()
	matches := detector.Match(map[string]string{"cf-ray": "abc-SJC"}, nil, 200)
	if len(matches) != 1 {
		t.Fatalf("matches = %v", matches)
	}
	if matches[0].Vendor != "cloudflare" || matches[0].Confidence != "medium" {
		t.Fatalf("match = %+v", matches[0])
	}
}

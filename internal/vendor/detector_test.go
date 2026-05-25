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

func TestSetCookieParsingDoesNotTreatAttributesAsCookieNames(t *testing.T) {
	names := cookieNames(map[string]string{
		"set-cookie": "sid=abc; Path=/; Secure; Partitioned\ncsrf=xyz; SameSite=None",
	})
	for _, want := range []string{"sid", "csrf"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing cookie %q in %#v", want, names)
		}
	}
	for _, unwanted := range []string{"path", "secure", "partitioned", "samesite"} {
		if _, ok := names[unwanted]; ok {
			t.Fatalf("cookie attribute %q treated as cookie name: %#v", unwanted, names)
		}
	}
}

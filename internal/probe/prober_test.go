package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestRunHermeticBasicProbeResponses(t *testing.T) {
	var getRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		getRequests.Add(1)
		w.Header().Set("content-type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()

	assessment, err := Run(context.Background(), server.URL, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.URL != server.URL {
		t.Fatalf("url = %q, want %q", assessment.URL, server.URL)
	}
	if assessment.Verdict != model.NoProtection {
		t.Fatalf("verdict = %s, recommendation = %q", assessment.Verdict, assessment.Recommendation)
	}
	if len(assessment.Results) != 3 {
		t.Fatalf("results length = %d, want 3", len(assessment.Results))
	}
	for _, result := range assessment.Results {
		if result.Status != http.StatusOK || result.Error != "" {
			t.Fatalf("result = %#v, want 200 without error", result)
		}
	}
	if getRequests.Load() != 3 {
		t.Fatalf("GET requests = %d, want 3", getRequests.Load())
	}
}

func TestRunHermeticChallengeAndBlockDetection(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantVerdict model.ProbeVerdict
	}{
		{
			name:        "all challenge",
			status:      http.StatusOK,
			body:        `<html><script src="https://challenges.cloudflare.com/challenge-platform"></script></html>`,
			wantVerdict: model.JSChallenge,
		},
		{
			name:        "all blocked",
			status:      http.StatusForbidden,
			body:        "forbidden",
			wantVerdict: model.FullBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			assessment, err := Run(context.Background(), server.URL, Options{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if assessment.Verdict != tt.wantVerdict {
				t.Fatalf("verdict = %s, want %s; recommendation = %q", assessment.Verdict, tt.wantVerdict, assessment.Recommendation)
			}
		})
	}
}

func TestRunDetectsVendorFromResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("cf-ray", "abc123-SJC")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	assessment, err := Run(context.Background(), server.URL, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(assessment.Vendors) != 1 {
		t.Fatalf("vendors = %#v, want one cloudflare match", assessment.Vendors)
	}
	if assessment.Vendors[0].Vendor != "cloudflare" || assessment.Vendors[0].Confidence != "medium" {
		t.Fatalf("vendor = %#v, want cloudflare medium", assessment.Vendors[0])
	}
	if !strings.Contains(assessment.Recommendation, "cloudflare") {
		t.Fatalf("recommendation = %q, want vendor prefix", assessment.Recommendation)
	}
}

func TestDetectGraphQLHermeticSuccessAndFailure(t *testing.T) {
	var introspectionRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var payload struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode graphql payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("content-type", "application/json")
		switch {
		case strings.Contains(payload.Query, "__schema"):
			introspectionRequests.Add(1)
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
		case strings.Contains(payload.Query, "__typename"):
			w.Write([]byte(`{"data":{"__typename":"Query"}}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	success := DetectGraphQL(context.Background(), server.URL, Options{Timeout: time.Second})
	if len(success.Endpoints) != 1 || success.Endpoints[0] != "/graphql" || !success.Introspection {
		t.Fatalf("success = %#v", success)
	}
	if introspectionRequests.Load() != 1 {
		t.Fatalf("introspection requests = %d, want 1", introspectionRequests.Load())
	}

	failure := DetectGraphQL(context.Background(), server.URL+"/missing", Options{Timeout: time.Second})
	if len(failure.Endpoints) != 0 || failure.Introspection {
		t.Fatalf("failure = %#v, want no endpoints and no introspection", failure)
	}
}

func TestDetectRateLimitHermeticDetection(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-client-token"); got != "probe-secret" {
			t.Errorf("x-client-token = %q, want probe-secret", got)
		}
		if count.Add(1) >= 3 {
			w.Header().Set("retry-after", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rateLimit, results := DetectRateLimit(
		context.Background(),
		server.URL,
		Options{
			Headers: map[string]string{"x-client-token": "probe-secret"},
			Timeout: time.Second,
		},
		RateOptions{Requests: 5, Concurrency: 1},
	)

	if len(results) != 5 || rateLimit.RequestsSent != 5 {
		t.Fatalf("results = %d requests = %d, want 5", len(results), rateLimit.RequestsSent)
	}
	if rateLimit.FirstBlockAt != 3 || rateLimit.BlockStatus != http.StatusTooManyRequests || rateLimit.RetryAfter != "30" {
		t.Fatalf("rate limit = %#v", rateLimit)
	}
}

func TestRunForwardsCustomHeadersAndCookie(t *testing.T) {
	var checked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "secret" {
			t.Errorf("%s %s x-api-key = %q, want secret", r.Method, r.URL.Path, got)
		}
		if got := r.Header.Get("cookie"); got != "session=abc" {
			t.Errorf("%s %s cookie = %q, want session=abc", r.Method, r.URL.Path, got)
		}
		checked.Add(1)
		if r.Method == http.MethodPost && r.URL.Path == "/graphql" {
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	assessment, err := Run(
		context.Background(),
		server.URL,
		Options{
			Headers: map[string]string{"x-api-key": "secret"},
			Cookie:  "session=abc",
			Timeout: time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Verdict != model.NoProtection {
		t.Fatalf("verdict = %s; assessment = %#v", assessment.Verdict, assessment)
	}
	if checked.Load() < 4 {
		t.Fatalf("checked requests = %d, want at least probe and graphql traffic", checked.Load())
	}
	if assessment.GraphQL == nil || len(assessment.GraphQL.Endpoints) != 1 {
		t.Fatalf("graphql = %#v, want forwarded-header graphql detection", assessment.GraphQL)
	}
}

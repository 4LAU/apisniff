package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDetectRateLimitRecords429AndRetryAfter(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "secret" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("cookie"); got != "session=abc" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if count.Add(1) >= 4 {
			w.Header().Set("retry-after", "7")
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
			Headers: map[string]string{"x-api-key": "secret"},
			Cookie:  "session=abc",
			Timeout: time.Second,
		},
		RateOptions{Requests: 6},
	)

	if len(results) != 6 {
		t.Fatalf("results length = %d, want 6", len(results))
	}
	if rateLimit.RequestsSent != 6 {
		t.Fatalf("requests sent = %d, want 6", rateLimit.RequestsSent)
	}
	if rateLimit.FirstBlockAt != 4 {
		t.Fatalf("first block at = %d, want 4", rateLimit.FirstBlockAt)
	}
	if rateLimit.BlockStatus != http.StatusTooManyRequests {
		t.Fatalf("block status = %d, want %d", rateLimit.BlockStatus, http.StatusTooManyRequests)
	}
	if rateLimit.RetryAfter != "7" {
		t.Fatalf("retry after = %q, want 7", rateLimit.RetryAfter)
	}
	if results[3].Variant != "rate_4" {
		t.Fatalf("variant = %q, want rate_4", results[3].Variant)
	}
}

func TestDetectRateLimitDetectsSilentThrottle(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) > 4 {
			time.Sleep(60 * time.Millisecond)
		} else {
			time.Sleep(5 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rateLimit, _ := DetectRateLimit(
		context.Background(),
		server.URL,
		Options{Timeout: time.Second},
		RateOptions{Requests: 6, Concurrency: 1},
	)

	if !rateLimit.SilentThrottle {
		t.Fatalf("silent throttle = false, want true; result = %#v", rateLimit)
	}
	if rateLimit.FirstBlockAt != 0 || rateLimit.BlockStatus != 0 {
		t.Fatalf("unexpected explicit block in result: %#v", rateLimit)
	}
	if rateLimit.MedianMS <= 0 {
		t.Fatalf("median ms = %f, want positive", rateLimit.MedianMS)
	}
}

func TestDetectRateLimitUsesConfiguredConcurrency(t *testing.T) {
	var current atomic.Int32
	var maxSeen atomic.Int32
	var total atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inFlight := current.Add(1)
		for {
			max := maxSeen.Load()
			if inFlight <= max || maxSeen.CompareAndSwap(max, inFlight) {
				break
			}
		}
		total.Add(1)
		time.Sleep(30 * time.Millisecond)
		current.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rateLimit, results := DetectRateLimit(
		context.Background(),
		server.URL,
		Options{Timeout: time.Second},
		RateOptions{Requests: 8, Concurrency: 4},
	)

	if total.Load() != 8 {
		t.Fatalf("total requests = %d, want 8", total.Load())
	}
	if len(results) != 8 || rateLimit.RequestsSent != 8 {
		t.Fatalf("result count = %d requests sent = %d, want 8", len(results), rateLimit.RequestsSent)
	}
	if maxSeen.Load() < 2 {
		t.Fatalf("max concurrency = %d, want at least 2", maxSeen.Load())
	}
}

func TestRunRateReturnsAssessmentWithNormalizedURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	assessment, err := RunRate(
		context.Background(),
		server.URL,
		Options{Timeout: time.Second},
		RateOptions{Requests: 2},
	)
	if err != nil {
		t.Fatalf("RunRate returned error: %v", err)
	}
	if assessment.URL != server.URL {
		t.Fatalf("url = %q, want %q", assessment.URL, server.URL)
	}
	if assessment.RateLimit == nil || assessment.RateLimit.RequestsSent != 2 {
		t.Fatalf("rate limit result = %#v, want 2 requests", assessment.RateLimit)
	}
	if len(assessment.Results) != 2 {
		t.Fatalf("results length = %d, want 2", len(assessment.Results))
	}
}

func TestDetectRateLimitStopsWhenContextCanceled(t *testing.T) {
	var total atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rateLimit, results := DetectRateLimit(
		ctx,
		server.URL,
		Options{Timeout: time.Second},
		RateOptions{Requests: 50, Concurrency: 4},
	)

	if total.Load() != 0 {
		t.Fatalf("server saw %d requests, want 0", total.Load())
	}
	if len(results) != 0 || rateLimit.RequestsSent != 0 {
		t.Fatalf("results length = %d requests sent = %d, want 0", len(results), rateLimit.RequestsSent)
	}
}

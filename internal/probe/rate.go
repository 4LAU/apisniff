package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/4LAU/apisniff-go/internal/model"
)

const (
	defaultRateRequests    = 20
	defaultRateConcurrency = 1
	maxRateConcurrency     = 16
	silentThrottleFactor   = 3
	silentThrottleMinDelta = 25 * time.Millisecond
)

type RateOptions struct {
	Requests    int
	Concurrency int
}

func RunRate(ctx context.Context, target string, opts Options, rateOpts RateOptions) (*model.ProbeAssessment, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	target = normalizeTargetURL(target)
	rateLimit, results := DetectRateLimit(ctx, target, opts, rateOpts)
	return &model.ProbeAssessment{
		URL:       target,
		Results:   results,
		RateLimit: rateLimit,
	}, nil
}

func DetectRateLimit(ctx context.Context, target string, opts Options, rateOpts RateOptions) (*model.RateLimitResult, []model.ProbeResult) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	target = normalizeTargetURL(target)
	rateOpts = normalizeRateOptions(rateOpts)

	client, cleanup, err := rateHTTPClient(opts)
	if err != nil {
		results := make([]model.ProbeResult, rateOpts.Requests)
		for i := range results {
			results[i] = model.ProbeResult{
				Variant: fmt.Sprintf("rate_%d", i+1),
				Error:   err.Error(),
			}
		}
		return summarizeRateResults(results), results
	}
	defer cleanup()

	if rateOpts.Concurrency == 1 {
		results := make([]model.ProbeResult, 0, rateOpts.Requests)
		for i := 0; i < rateOpts.Requests; i++ {
			if ctx.Err() != nil {
				break
			}
			results = append(results, runRateRequest(ctx, client, target, opts, i))
		}
		return summarizeRateResults(results), results
	}

	results := make([]model.ProbeResult, rateOpts.Requests)
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < rateOpts.Concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = runRateRequest(ctx, client, target, opts, i)
			}
		}()
	}
	sent := 0
dispatch:
	for i := 0; i < rateOpts.Requests; i++ {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- i:
			sent++
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()

	return summarizeRateResults(results[:sent]), results[:sent]
}

func normalizeRateOptions(rateOpts RateOptions) RateOptions {
	if rateOpts.Requests <= 0 {
		rateOpts.Requests = defaultRateRequests
	}
	if rateOpts.Concurrency <= 0 {
		rateOpts.Concurrency = defaultRateConcurrency
	}
	if rateOpts.Concurrency > maxRateConcurrency {
		rateOpts.Concurrency = maxRateConcurrency
	}
	if rateOpts.Concurrency > rateOpts.Requests {
		rateOpts.Concurrency = rateOpts.Requests
	}
	return rateOpts
}

func rateHTTPClient(opts Options) (*http.Client, func(), error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec
	}
	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, func() {}, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Timeout: opts.Timeout, Transport: transport}, transport.CloseIdleConnections, nil
}

func runRateRequest(ctx context.Context, client *http.Client, target string, opts Options, index int) model.ProbeResult {
	result := doHTTP(ctx, client, target, botUA, opts)
	result.Variant = fmt.Sprintf("rate_%d", index+1)
	return result
}

func summarizeRateResults(results []model.ProbeResult) *model.RateLimitResult {
	summary := &model.RateLimitResult{
		RequestsSent: len(results),
		MedianMS:     medianLatencyMS(results),
	}
	for i, result := range results {
		if result.Status == http.StatusTooManyRequests {
			summary.FirstBlockAt = i + 1
			summary.BlockStatus = result.Status
			summary.RetryAfter = model.GetHeader(result.Headers, "retry-after")
			break
		}
	}
	if summary.BlockStatus == 0 {
		summary.SilentThrottle = detectSilentThrottle(results)
	}
	return summary
}

func detectSilentThrottle(results []model.ProbeResult) bool {
	successLatencies := make([]time.Duration, 0, len(results))
	for _, result := range results {
		if result.Error == "" && result.Status > 0 && result.Status != http.StatusTooManyRequests {
			successLatencies = append(successLatencies, result.Latency)
		}
	}
	if len(successLatencies) < 6 {
		return false
	}
	baselineCount := len(successLatencies) / 3
	laterCount := len(successLatencies) / 3
	if baselineCount == 0 || laterCount == 0 {
		return false
	}
	baseline := medianDuration(successLatencies[:baselineCount])
	later := medianDuration(successLatencies[len(successLatencies)-laterCount:])
	return later >= baseline*silentThrottleFactor && later-baseline >= silentThrottleMinDelta
}

func medianLatencyMS(results []model.ProbeResult) float64 {
	latencies := make([]time.Duration, 0, len(results))
	for _, result := range results {
		if result.Latency > 0 {
			latencies = append(latencies, result.Latency)
		}
	}
	if len(latencies) == 0 {
		return 0
	}
	return float64(medianDuration(latencies)) / float64(time.Millisecond)
}

func medianDuration(values []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

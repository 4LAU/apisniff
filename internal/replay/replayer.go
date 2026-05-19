package replay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/4LAU/apisniff-go/internal/adapter"
	"github.com/4LAU/apisniff-go/internal/capture"
	"github.com/4LAU/apisniff-go/internal/model"
	"github.com/enetx/surf"
)

var hopByHop = map[string]struct{}{"host": {}, "content-length": {}, "content-encoding": {}, "transfer-encoding": {}, "connection": {}, "keep-alive": {}}
var authHeaders = map[string]struct{}{"authorization": {}, "cookie": {}, "x-api-key": {}, "api-key": {}, "apikey": {}}
var safeMethods = map[string]struct{}{"GET": {}, "HEAD": {}, "OPTIONS": {}}

type Options struct {
	BundleOrDomain string
	Filter         string
	Timeout        time.Duration
	CookieFile     string
	Headers        map[string]string
	Impersonate    string
	IncludeUnsafe  bool
	Insecure       bool
	DryRun         bool
}

type Result struct {
	Method         string         `json:"method"`
	Path           string         `json:"path"`
	URL            string         `json:"url"`
	OriginalStatus int            `json:"original_status"`
	ReplayedStatus int            `json:"replayed_status,omitempty"`
	ElapsedMS      float64        `json:"elapsed_ms"`
	Error          string         `json:"error,omitempty"`
	Category       string         `json:"category"`
	StatusMatch    bool           `json:"status_match"`
	BodyShapeMatch bool           `json:"body_shape_match"`
	BodyShapeDiff  map[string]any `json:"body_shape_diff,omitempty"`
	SizeOriginal   int            `json:"size_original"`
	SizeReplayed   int            `json:"size_replayed"`
}

type Summary struct {
	SchemaVersion int            `json:"schema_version"`
	Mode          string         `json:"mode,omitempty"`
	Domain        string         `json:"domain,omitempty"`
	Summary       map[string]int `json:"summary"`
	Results       []Result       `json:"results,omitempty"`
	Endpoints     []string       `json:"endpoints,omitempty"`
}

func Run(ctx context.Context, opts Options) (Summary, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	flowsPath, domain, err := resolveFlowsPath(opts.BundleOrDomain)
	if err != nil {
		return Summary{}, err
	}
	flows, err := adapter.LoadJSONL(flowsPath)
	if err != nil {
		return Summary{}, err
	}
	filtered := filterByPattern(deduplicate(flows), opts.Filter)
	safe, unsafe := FilterFlows(filtered, opts.IncludeUnsafe)
	if opts.DryRun {
		endpoints := make([]string, 0, len(filtered))
		for _, flow := range filtered {
			endpoints = append(endpoints, strings.ToUpper(flow.Method)+" "+flow.Path)
		}
		sort.Strings(endpoints)
		return Summary{
			SchemaVersion: 1,
			Mode:          "dry_run",
			Domain:        domain,
			Summary:       map[string]int{"safe": len(safe), "unsafe": len(unsafe), "total": len(filtered)},
			Endpoints:     endpoints,
		}, nil
	}

	var cookies []Cookie
	if opts.CookieFile != "" {
		cookies, err = ParseCookieFile(opts.CookieFile)
		if err != nil {
			return Summary{}, err
		}
	}
	client, err := newHTTPClient(opts)
	if err != nil {
		return Summary{}, err
	}
	defer client.CloseIdleConnections()
	httpClient := client.Std()

	results := make([]Result, 0, len(safe))
	summary := map[string]int{}
	for _, flow := range safe {
		result := ReplayOne(ctx, httpClient, flow, opts, cookies)
		results = append(results, result)
		summary[result.Category]++
	}
	return Summary{SchemaVersion: 1, Domain: domain, Summary: summary, Results: results}, nil
}

func newHTTPClient(opts Options) (*surf.Client, error) {
	builder := surf.NewClient().Builder().Timeout(opts.Timeout)
	if !opts.Insecure {
		builder = builder.SecureTLS()
	}
	profile := strings.ToLower(firstNonEmpty(opts.Impersonate, "chrome"))
	switch profile {
	case "chrome", "":
		return builder.Impersonate().Chrome().Build().Result()
	case "firefox":
		return builder.Impersonate().Firefox().Build().Result()
	default:
		return nil, fmt.Errorf("unsupported impersonate profile %q", opts.Impersonate)
	}
}

func ReplayOne(ctx context.Context, client *http.Client, flow model.CapturedFlow, opts Options, cookies []Cookie) Result {
	start := time.Now()
	req, err := buildRequest(ctx, flow, opts.Headers, cookies)
	if err != nil {
		return replayResult(flow, 0, nil, time.Since(start), err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return replayResult(flow, 0, nil, time.Since(start), err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if readErr != nil {
		err = readErr
	}
	return replayResult(flow, resp.StatusCode, body, time.Since(start), err)
}

func buildRequest(ctx context.Context, flow model.CapturedFlow, headers map[string]string, cookies []Cookie) (*http.Request, error) {
	host, err := requestHost(flow)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if len(flow.RequestBody) > 0 {
		body = bytes.NewReader(flow.RequestBody)
	}
	req, err := http.NewRequestWithContext(ctx, flow.Method, flow.URL, body)
	if err != nil {
		return nil, err
	}
	for key, value := range flow.RequestHeaders {
		if _, skip := hopByHop[strings.ToLower(key)]; skip {
			continue
		}
		req.Header.Set(key, value)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if cookieHeader := CookiesForHost(cookies, host); cookieHeader != "" {
		existing := req.Header.Get("cookie")
		if existing != "" {
			req.Header.Set("cookie", existing+"; "+cookieHeader)
		} else {
			req.Header.Set("cookie", cookieHeader)
		}
	}
	return req, nil
}

func replayResult(flow model.CapturedFlow, status int, body []byte, elapsed time.Duration, err error) Result {
	bodyMatch, diff := CompareShape(flow.ResponseBody, body)
	category, statusMatch := AssignCategory(flow.ResponseStatus, status, hasAuthHeaders(flow), bodyMatch, len(flow.ResponseBody), len(body), err)
	result := Result{
		Method:         flow.Method,
		Path:           flow.Path,
		URL:            flow.URL,
		OriginalStatus: flow.ResponseStatus,
		ReplayedStatus: status,
		ElapsedMS:      float64(elapsed.Microseconds()) / 1000,
		Category:       category,
		StatusMatch:    statusMatch,
		BodyShapeMatch: bodyMatch,
		BodyShapeDiff:  diff,
		SizeOriginal:   len(flow.ResponseBody),
		SizeReplayed:   len(body),
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func FilterFlows(flows []model.CapturedFlow, includeUnsafe bool) ([]model.CapturedFlow, []model.CapturedFlow) {
	if includeUnsafe {
		return flows, nil
	}
	var safe []model.CapturedFlow
	var unsafe []model.CapturedFlow
	for _, flow := range flows {
		if _, ok := safeMethods[strings.ToUpper(flow.Method)]; ok {
			safe = append(safe, flow)
		} else {
			unsafe = append(unsafe, flow)
		}
	}
	return safe, unsafe
}

func resolveFlowsPath(bundleOrDomain string) (string, string, error) {
	if bundleOrDomain == "" {
		return "", "", fmt.Errorf("bundle or domain is required")
	}
	if fileExists(bundleOrDomain) {
		return bundleOrDomain, domainFromFlowsPath(bundleOrDomain), nil
	}
	if abs, err := filepath.Abs(bundleOrDomain); err == nil {
		flows := filepath.Join(abs, "flows.jsonl")
		if fileExists(flows) {
			return flows, filepath.Base(abs), nil
		}
	}
	safe := strings.NewReplacer(".", "-", "/", "-").Replace(bundleOrDomain)
	matches, _ := filepath.Glob(filepath.Join(capture.CapturesDir(), safe+"_*", "flows.jsonl"))
	if len(matches) == 0 {
		return "", bundleOrDomain, fmt.Errorf("no flows found for %s", bundleOrDomain)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches[0], bundleOrDomain, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func domainFromFlowsPath(path string) string {
	base := filepath.Base(filepath.Dir(path))
	if base == "." || base == string(filepath.Separator) {
		return ""
	}
	return base
}

func filterByPattern(flows []model.CapturedFlow, pattern string) []model.CapturedFlow {
	if pattern == "" {
		return flows
	}
	out := make([]model.CapturedFlow, 0, len(flows))
	for _, flow := range flows {
		if ok, _ := filepath.Match(pattern, flow.Path); ok {
			out = append(out, flow)
		}
	}
	return out
}

func deduplicate(flows []model.CapturedFlow) []model.CapturedFlow {
	seen := map[[2]string]model.CapturedFlow{}
	for _, flow := range flows {
		key := [2]string{strings.ToUpper(flow.Method), model.ReplayDedupKey(flow.Path)}
		if existing, ok := seen[key]; !ok || flow.Timestamp > existing.Timestamp {
			seen[key] = flow
		}
	}
	out := make([]model.CapturedFlow, 0, len(seen))
	for _, flow := range seen {
		out = append(out, flow)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Method < out[j].Method
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func requestHost(flow model.CapturedFlow) (string, error) {
	parsed, err := url.Parse(flow.URL)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(parsed.Hostname())
	expected := stripPort(strings.ToLower(flow.Host))
	if host == "" {
		return expected, nil
	}
	if expected != "" && host != expected {
		return "", fmt.Errorf("flow host mismatch: host=%q url host=%q", flow.Host, host)
	}
	return host, nil
}

func stripPort(host string) string {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return parsed
	}
	return host
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func hasAuthHeaders(flow model.CapturedFlow) bool {
	for key := range flow.RequestHeaders {
		if _, ok := authHeaders[strings.ToLower(key)]; ok {
			return true
		}
	}
	return false
}

package replay

import (
	"bytes"
	"context"
	"errors"
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

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/bundle"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/enetx/surf"
)

var hopByHop = map[string]struct{}{"host": {}, "content-length": {}, "content-encoding": {}, "transfer-encoding": {}, "connection": {}, "keep-alive": {}}
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
	ForwardAuth    bool
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
	Merges        []DedupMerge   `json:"merges,omitempty"`
}

func Run(ctx context.Context, opts Options) (Summary, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	flowsPath, domain, err := resolveReplayInput(opts.BundleOrDomain)
	if err != nil {
		return Summary{}, err
	}
	flows, err := adapter.LoadJSONL(flowsPath)
	if err != nil {
		return Summary{}, err
	}
	deduped, merges := deduplicate(flows)
	filtered, err := filterByPattern(deduped, opts.Filter)
	if err != nil {
		return Summary{}, err
	}
	safe, unsafe := FilterFlows(filtered, opts.IncludeUnsafe)
	if opts.DryRun {
		endpoints := make([]string, 0, len(filtered))
		for _, flow := range filtered {
			// Query strings can carry credentials; the endpoint list never
			// needs them, so drop the whole query.
			path, _, _ := strings.Cut(flow.Path, "?")
			endpoints = append(endpoints, strings.ToUpper(flow.Method)+" "+path)
		}
		sort.Strings(endpoints)
		return Summary{
			SchemaVersion: 1,
			Mode:          "dry_run",
			Domain:        domain,
			Summary:       map[string]int{"safe": len(safe), "unsafe": len(unsafe), "total": len(filtered)},
			Endpoints:     endpoints,
			Merges:        merges,
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
	return Summary{SchemaVersion: 1, Domain: domain, Summary: summary, Results: results, Merges: merges}, nil
}

func newHTTPClient(opts Options) (*surf.Client, error) {
	builder := surf.NewClient().Builder().Timeout(opts.Timeout)
	if !opts.Insecure {
		builder = builder.SecureTLS()
	}
	switch strings.ToLower(opts.Impersonate) {
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
	req, err := buildRequest(ctx, flow, opts.Headers, cookies, opts.ForwardAuth)
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

func buildRequest(ctx context.Context, flow model.CapturedFlow, headers map[string]string, cookies []Cookie, forwardAuth bool) (*http.Request, error) {
	host, err := requestHost(flow)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if len(flow.RequestBody) > 0 {
		body = bytes.NewReader(flow.RequestBody)
	}
	targetURL := flow.URL
	if !forwardAuth {
		// Credentials in the URL come in two forms: query strings
		// (?api_key=, ?access_token=) and Basic-auth userinfo
		// (user:pass@host, which net/http would resend as an
		// Authorization header). Strip both.
		targetURL = auth.StripURLCredentials(targetURL)
	}
	req, err := http.NewRequestWithContext(ctx, flow.Method, targetURL, body)
	if err != nil {
		return nil, err
	}
	for key, value := range flow.RequestHeaders {
		lower := strings.ToLower(key)
		if _, skip := hopByHop[lower]; skip {
			continue
		}
		if !forwardAuth {
			if isAuthHeader(lower) {
				continue
			}
		}
		// Proxy capture joins duplicate header values with "\n"; a raw
		// newline in a header value is rejected by net/http.
		for _, v := range strings.Split(value, "\n") {
			req.Header.Add(key, v)
		}
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
	category, statusMatch := AssignCategory(flow.ResponseStatus, status, hadCredentials(flow), bodyMatch, len(flow.ResponseBody), len(body), err)
	result := Result{
		Method: flow.Method,
		// Reports are meant to be shareable: never echo the captured
		// credential query params (?api_key=, ?access_token=) back out.
		Path:           stripForOutput(flow.Path),
		URL:            stripForOutput(flow.URL),
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
		result.Error = sanitizeErrorString(err)
	}
	return result
}

// sanitizeErrorString strips credential query values from a replay error
// before it lands in shareable output: a *url.Error embeds the full request
// URL, which under --forward-auth still carries credential params.
func sanitizeErrorString(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		clean := *urlErr
		clean.URL = stripForOutput(urlErr.URL)
		return clean.Error()
	}
	return err.Error()
}

// stripForOutput removes captured credentials from every credential-bearing
// component of a URL before it lands in shareable output: userinfo
// (user:pass@), credential fragments (#access_token=... from OAuth implicit
// flow), and credential query params (?api_key=...). Request-building strips
// only the query (see buildRequest); output must scrub all three so the
// report never echoes a captured secret.
//
// Unlike request-building — where an unparseable URL passes through so the
// request construction surfaces the error — output must fail closed: if the
// URL cannot be parsed, drop everything from the first "?" or "#" rather than
// echoing it raw.
func stripForOutput(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
			return rawURL[:i]
		}
		return rawURL
	}
	// Userinfo (user:pass@) is a credential; never echo it.
	parsed.User = nil
	// A fragment holds OAuth implicit-flow tokens (#access_token=...). If it
	// parses as key=value pairs and any key is a credential, drop the whole
	// fragment.
	if fragmentHasCredential(parsed.Fragment) {
		parsed.Fragment = ""
		parsed.RawFragment = ""
	}
	// Reuse the auth policy for query stripping so the two never diverge.
	return auth.StripCredentialQueryParams(parsed.String())
}

// fragmentHasCredential reports whether a URL fragment, read as
// k=v(&k=v)* pairs, contains any key the forwarding policy treats as a
// credential.
func fragmentHasCredential(fragment string) bool {
	if fragment == "" {
		return false
	}
	for _, pair := range strings.Split(fragment, "&") {
		name, _, _ := strings.Cut(pair, "=")
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		if auth.IsCredentialQueryParam(name) {
			return true
		}
	}
	return false
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

func resolveReplayInput(bundleOrDomain string) (string, string, error) {
	if bundleOrDomain == "" {
		return "", "", fmt.Errorf("bundle or domain is required")
	}
	if fileExists(bundleOrDomain) {
		return bundleOrDomain, domainFromFlowsPath(bundleOrDomain), nil
	}
	resolved, err := bundle.Resolve(bundleOrDomain)
	if err != nil {
		return "", bundleOrDomain, err
	}
	flowsPath := filepath.Join(resolved.Path, "flows.jsonl")
	if !fileExists(flowsPath) {
		return "", bundleDomain(resolved, bundleOrDomain), fmt.Errorf("no flows found for %s", bundleOrDomain)
	}
	return flowsPath, bundleDomain(resolved, bundleOrDomain), nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func bundleDomain(resolved bundle.Bundle, fallback string) string {
	if resolved.Domain != "" {
		return resolved.Domain
	}
	if resolved.SafeName != "" {
		return resolved.SafeName
	}
	return fallback
}

func domainFromFlowsPath(path string) string {
	base := filepath.Base(filepath.Dir(path))
	if base == "." || base == string(filepath.Separator) {
		return ""
	}
	return base
}

func filterByPattern(flows []model.CapturedFlow, pattern string) ([]model.CapturedFlow, error) {
	if pattern == "" {
		return flows, nil
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, fmt.Errorf("invalid filter pattern %q: %w", pattern, err)
	}
	out := make([]model.CapturedFlow, 0, len(flows))
	for _, flow := range flows {
		if ok, _ := filepath.Match(pattern, flow.Path); ok {
			out = append(out, flow)
		}
	}
	return out, nil
}

// DedupMerge records that two or more captured raw paths collapsed into one
// replay key. Surfaced in Summary so a collapse — and any false-positive route
// drop it might cause — is never silent.
type DedupMerge struct {
	Method string   `json:"method"`
	Key    string   `json:"key"`
	Paths  []string `json:"paths"`
}

func deduplicate(flows []model.CapturedFlow) ([]model.CapturedFlow, []DedupMerge) {
	seen := map[[2]string]model.CapturedFlow{}
	rawPaths := map[[2]string]map[string]struct{}{}
	for _, flow := range flows {
		key := [2]string{strings.ToUpper(flow.Method), model.ReplayDedupKey(flow.Path)}
		if existing, ok := seen[key]; !ok || flow.Timestamp > existing.Timestamp {
			seen[key] = flow
		}
		if rawPaths[key] == nil {
			rawPaths[key] = map[string]struct{}{}
		}
		rawPaths[key][flow.Path] = struct{}{}
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

	var merges []DedupMerge
	for key, paths := range rawPaths {
		if len(paths) < 2 {
			continue
		}
		// Merge paths land in shareable report output; strip credential
		// query values before emitting. Distinct raw paths may collapse to a
		// single stripped entry (e.g. two token values) — the merge is still
		// reported so the collapse is never silent.
		stripped := map[string]struct{}{}
		for p := range paths {
			stripped[stripForOutput(p)] = struct{}{}
		}
		ps := make([]string, 0, len(stripped))
		for p := range stripped {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		merges = append(merges, DedupMerge{Method: key[0], Key: key[1], Paths: ps})
	}
	sort.Slice(merges, func(i, j int) bool {
		if merges[i].Method == merges[j].Method {
			return merges[i].Key < merges[j].Key
		}
		return merges[i].Method < merges[j].Method
	})
	return out, merges
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

// hadCredentials must match the stripping policy in buildRequest: a flow whose
// auth lived only in a query param (?access_token=...) replays without it, and
// a 401 there is auth_expired, not blocked. Over-matching a benign param named
// "token" is acceptable — recall over precision, same as the stripping itself.
func hadCredentials(flow model.CapturedFlow) bool {
	if hasAuthHeaders(flow) {
		return true
	}
	parsed, err := url.Parse(flow.URL)
	if err != nil {
		return false
	}
	for name := range parsed.Query() {
		if auth.IsCredentialQueryParam(name) {
			return true
		}
	}
	return false
}

func hasAuthHeaders(flow model.CapturedFlow) bool {
	for key := range flow.RequestHeaders {
		if isAuthHeader(key) {
			return true
		}
	}
	return false
}

func isAuthHeader(key string) bool {
	return auth.IsCredentialHeader(key)
}

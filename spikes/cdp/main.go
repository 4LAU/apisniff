package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type capturedFlow struct {
	Method          string            `json:"method"`
	Host            string            `json:"host"`
	Path            string            `json:"path"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     *string           `json:"request_body"`
	ResponseStatus  int64             `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    *string           `json:"response_body"`
	BodyEncoding    string            `json:"_body_encoding"`
	Tags            []string          `json:"tags"`
	Timestamp       float64           `json:"timestamp"`
}

type partialFlow struct {
	flow      capturedFlow
	requestID network.RequestID
	bodyErr   string
}

type findings struct {
	GeneratedAt       time.Time       `json:"generated_at"`
	Mode              string          `json:"mode"`
	URL               string          `json:"url"`
	RemoteDebugPort   int             `json:"remote_debugging_port,omitempty"`
	UserDataDir       string          `json:"user_data_dir,omitempty"`
	RemoteURL         string          `json:"remote_url,omitempty"`
	Headless          bool            `json:"headless"`
	Chrome            chromeVersion   `json:"chrome"`
	NavigatorWebdrive webdriverResult `json:"navigator_webdriver"`
	Counts            captureCounts   `json:"counts"`
	BodyFailures      []bodyFailure   `json:"body_failures,omitempty"`
	LoadingFailures   []loadFailure   `json:"loading_failures,omitempty"`
	Notes             []string        `json:"notes"`
}

type chromeVersion struct {
	ProtocolVersion string `json:"protocol_version,omitempty"`
	Product         string `json:"product,omitempty"`
	Revision        string `json:"revision,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	JSVersion       string `json:"js_version,omitempty"`
	Error           string `json:"error,omitempty"`
}

type webdriverResult struct {
	Value *bool  `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

type captureCounts struct {
	Requests          int `json:"requests"`
	Responses         int `json:"responses"`
	FlowsWritten      int `json:"flows_written"`
	ResponseBodies    int `json:"response_bodies"`
	RequestBodies     int `json:"request_bodies"`
	WebSocketSent     int `json:"websocket_sent"`
	WebSocketReceived int `json:"websocket_received"`
	EventSource       int `json:"event_source"`
	ServedFromCache   int `json:"served_from_cache"`
	ServiceWorker     int `json:"service_worker"`
}

type bodyFailure struct {
	RequestID string `json:"request_id"`
	URL       string `json:"url,omitempty"`
	Error     string `json:"error"`
}

type loadFailure struct {
	RequestID string `json:"request_id"`
	URL       string `json:"url,omitempty"`
	ErrorText string `json:"error_text"`
	Canceled  bool   `json:"canceled"`
}

type recorder struct {
	mu           sync.Mutex
	flows        map[network.RequestID]*partialFlow
	order        []network.RequestID
	counts       captureCounts
	bodyFailures []bodyFailure
	loadFailures []loadFailure
	bodyWG       sync.WaitGroup
}

func main() {
	mode := flag.String("mode", "launch", "capture mode: launch or attach")
	targetURL := flag.String("url", "https://example.com", "URL to navigate to")
	outPath := flag.String("out", "flows.jsonl", "CapturedFlow-compatible JSONL output path")
	findingsPath := flag.String("findings", "findings.json", "capture findings output path (.json or .md)")
	remoteURL := flag.String("remote-url", "http://127.0.0.1:9222", "Chrome DevTools remote URL for attach mode")
	userDataDir := flag.String("user-data-dir", defaultUserDataDir(), "Chrome user data dir for launch mode")
	remoteDebuggingPort := flag.Int("remote-debugging-port", 9222, "remote debugging port for launch mode; use 0 to test Chrome-assigned port behavior")
	headless := flag.Bool("headless", false, "run launched Chrome headless")
	wait := flag.Duration("wait", 5*time.Second, "extra wait after navigation for async network activity")
	timeout := flag.Duration("timeout", 45*time.Second, "overall capture timeout")
	flag.Parse()

	ctx, cancel, err := newBrowserContext(*mode, *remoteURL, *userDataDir, *remoteDebuggingPort, *headless, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "browser context: %v\n", err)
		os.Exit(2)
	}
	defer cancel()

	rec := &recorder{flows: make(map[network.RequestID]*partialFlow)}
	chromedp.ListenTarget(ctx, rec.listen(ctx))

	runErr := chromedp.Run(ctx,
		network.Enable().
			WithMaxTotalBufferSize(100*1024*1024).
			WithMaxResourceBufferSize(25*1024*1024),
		chromedp.Navigate(*targetURL),
		chromedp.Sleep(*wait),
	)
	rec.bodyWG.Wait()

	version := getChromeVersion(ctx)
	webdriver := getNavigatorWebdriver(ctx)

	flows := rec.snapshotFlows()
	if err := writeJSONL(*outPath, flows); err != nil {
		fmt.Fprintf(os.Stderr, "write flows: %v\n", err)
		os.Exit(1)
	}

	report := findings{
		GeneratedAt:       time.Now().UTC(),
		Mode:              *mode,
		URL:               *targetURL,
		RemoteDebugPort:   *remoteDebuggingPort,
		UserDataDir:       *userDataDir,
		RemoteURL:         *remoteURL,
		Headless:          *headless,
		Chrome:            version,
		NavigatorWebdrive: webdriver,
		Counts:            rec.snapshotCounts(len(flows)),
		BodyFailures:      rec.snapshotBodyFailures(),
		LoadingFailures:   rec.snapshotLoadFailures(),
		Notes:             phase0Notes(runErr),
	}
	if err := writeFindings(*findingsPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "write findings: %v\n", err)
		os.Exit(1)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "capture completed with navigation error: %v\n", runErr)
		os.Exit(1)
	}
}

func newBrowserContext(mode, remoteURL, userDataDir string, port int, headless bool, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	root, rootCancel := context.WithTimeout(context.Background(), timeout)

	switch mode {
	case "attach":
		allocCtx, allocCancel := chromedp.NewRemoteAllocator(root, remoteURL)
		ctx, ctxCancel := chromedp.NewContext(allocCtx)
		return ctx, func() {
			ctxCancel()
			allocCancel()
			rootCancel()
		}, nil
	case "launch":
		if err := os.MkdirAll(userDataDir, 0o755); err != nil {
			rootCancel()
			return nil, nil, err
		}
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", headless),
			chromedp.Flag("remote-debugging-port", fmt.Sprintf("%d", port)),
			chromedp.UserDataDir(userDataDir),
			chromedp.NoFirstRun,
			chromedp.NoDefaultBrowserCheck,
		)
		allocCtx, allocCancel := chromedp.NewExecAllocator(root, opts...)
		ctx, ctxCancel := chromedp.NewContext(allocCtx)
		return ctx, func() {
			ctxCancel()
			allocCancel()
			rootCancel()
		}, nil
	default:
		rootCancel()
		return nil, nil, fmt.Errorf("unsupported mode %q", mode)
	}
}

func (r *recorder) listen(ctx context.Context) func(any) {
	return func(ev any) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			r.requestWillBeSent(ctx, ev)
		case *network.EventResponseReceived:
			r.responseReceived(ev)
		case *network.EventLoadingFinished:
			r.loadingFinished(ctx, ev)
		case *network.EventLoadingFailed:
			r.loadingFailed(ev)
		case *network.EventRequestServedFromCache:
			r.markCached(ev.RequestID)
		case *network.EventWebSocketFrameSent:
			r.increment(func(c *captureCounts) { c.WebSocketSent++ })
		case *network.EventWebSocketFrameReceived:
			r.increment(func(c *captureCounts) { c.WebSocketReceived++ })
		case *network.EventEventSourceMessageReceived:
			r.increment(func(c *captureCounts) { c.EventSource++ })
		}
	}
}

func (r *recorder) requestWillBeSent(ctx context.Context, ev *network.EventRequestWillBeSent) {
	reqURL, host, path := parseRequestURL(ev.Request.URL)
	flow := capturedFlow{
		Method:          ev.Request.Method,
		Host:            host,
		Path:            path,
		URL:             reqURL,
		RequestHeaders:  headersToStrings(ev.Request.Headers),
		RequestBody:     nil,
		ResponseStatus:  0,
		ResponseHeaders: map[string]string{},
		ResponseBody:    nil,
		BodyEncoding:    "base64",
		Tags:            []string{},
		Timestamp:       float64(time.Now().UnixNano()) / 1e9,
	}
	r.mu.Lock()
	if _, exists := r.flows[ev.RequestID]; !exists {
		r.order = append(r.order, ev.RequestID)
	}
	r.flows[ev.RequestID] = &partialFlow{flow: flow, requestID: ev.RequestID}
	r.counts.Requests++
	r.mu.Unlock()

	if ev.Request.HasPostData {
		r.requestPostData(ctx, ev.RequestID)
	}
}

func (r *recorder) requestPostData(ctx context.Context, id network.RequestID) {
	r.bodyWG.Add(1)
	go func() {
		defer r.bodyWG.Done()
		var postData []byte
		err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			postData, err = network.GetRequestPostData(id).Do(ctx)
			return err
		}))
		r.mu.Lock()
		defer r.mu.Unlock()
		pf, ok := r.flows[id]
		if !ok {
			return
		}
		if err != nil {
			pf.flow.Tags = appendTag(pf.flow.Tags, "request_body_error")
			r.bodyFailures = append(r.bodyFailures, bodyFailure{
				RequestID: id.String(),
				URL:       pf.flow.URL,
				Error:     "request post data: " + err.Error(),
			})
			return
		}
		if len(postData) > 0 {
			pf.flow.RequestBody = base64String(postData)
			r.counts.RequestBodies++
		}
	}()
}

func (r *recorder) responseReceived(ev *network.EventResponseReceived) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pf := r.ensureFlowLocked(ev.RequestID, ev.Response.URL)
	pf.flow.ResponseStatus = int64(ev.Response.Status)
	pf.flow.ResponseHeaders = headersToStrings(ev.Response.Headers)
	if ev.Response.FromDiskCache {
		pf.flow.Tags = appendTag(pf.flow.Tags, "served_from_cache")
		r.counts.ServedFromCache++
	}
	if ev.Response.FromServiceWorker {
		pf.flow.Tags = appendTag(pf.flow.Tags, "service_worker")
		r.counts.ServiceWorker++
	}
	if ev.Type.String() != "" {
		pf.flow.Tags = appendTag(pf.flow.Tags, "resource_type:"+ev.Type.String())
	}
	r.counts.Responses++
}

func (r *recorder) loadingFinished(ctx context.Context, ev *network.EventLoadingFinished) {
	r.bodyWG.Add(1)
	go func() {
		defer r.bodyWG.Done()
		var body []byte
		err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			body, err = network.GetResponseBody(ev.RequestID).Do(ctx)
			return err
		}))
		r.mu.Lock()
		defer r.mu.Unlock()
		pf, ok := r.flows[ev.RequestID]
		if !ok {
			return
		}
		if err != nil {
			msg := err.Error()
			pf.bodyErr = msg
			pf.flow.Tags = appendTag(pf.flow.Tags, "response_body_error")
			r.bodyFailures = append(r.bodyFailures, bodyFailure{
				RequestID: ev.RequestID.String(),
				URL:       pf.flow.URL,
				Error:     msg,
			})
			return
		}
		if len(body) > 0 {
			pf.flow.ResponseBody = base64String(body)
			r.counts.ResponseBodies++
		}
	}()
}

func (r *recorder) loadingFailed(ev *network.EventLoadingFailed) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pf := r.ensureFlowLocked(ev.RequestID, "")
	pf.flow.Tags = appendTag(pf.flow.Tags, "loading_failed")
	r.loadFailures = append(r.loadFailures, loadFailure{
		RequestID: ev.RequestID.String(),
		URL:       pf.flow.URL,
		ErrorText: ev.ErrorText,
		Canceled:  ev.Canceled,
	})
}

func (r *recorder) markCached(id network.RequestID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pf := r.ensureFlowLocked(id, "")
	pf.flow.Tags = appendTag(pf.flow.Tags, "served_from_cache")
	r.counts.ServedFromCache++
}

func (r *recorder) ensureFlowLocked(id network.RequestID, rawURL string) *partialFlow {
	if pf, ok := r.flows[id]; ok {
		return pf
	}
	reqURL, host, path := parseRequestURL(rawURL)
	flow := capturedFlow{
		Host:            host,
		Path:            path,
		URL:             reqURL,
		RequestHeaders:  map[string]string{},
		ResponseHeaders: map[string]string{},
		BodyEncoding:    "base64",
		Tags:            []string{"missing_request_event"},
		Timestamp:       float64(time.Now().UnixNano()) / 1e9,
	}
	pf := &partialFlow{flow: flow, requestID: id}
	r.flows[id] = pf
	r.order = append(r.order, id)
	return pf
}

func (r *recorder) increment(update func(*captureCounts)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	update(&r.counts)
}

func (r *recorder) snapshotFlows() []capturedFlow {
	r.mu.Lock()
	defer r.mu.Unlock()

	flows := make([]capturedFlow, 0, len(r.order))
	for _, id := range r.order {
		pf := r.flows[id]
		if pf == nil {
			continue
		}
		pf.flow.Tags = sortedTags(pf.flow.Tags)
		flows = append(flows, pf.flow)
	}
	return flows
}

func (r *recorder) snapshotCounts(flowCount int) captureCounts {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := r.counts
	counts.FlowsWritten = flowCount
	return counts
}

func (r *recorder) snapshotBodyFailures() []bodyFailure {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]bodyFailure(nil), r.bodyFailures...)
	sort.Slice(out, func(i, j int) bool { return out[i].RequestID < out[j].RequestID })
	return out
}

func (r *recorder) snapshotLoadFailures() []loadFailure {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]loadFailure(nil), r.loadFailures...)
	sort.Slice(out, func(i, j int) bool { return out[i].RequestID < out[j].RequestID })
	return out
}

func getChromeVersion(ctx context.Context) chromeVersion {
	var protocol, product, revision, ua, js string
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		protocol, product, revision, ua, js, err = browser.GetVersion().Do(ctx)
		return err
	}))
	if err != nil {
		return chromeVersion{Error: err.Error()}
	}
	return chromeVersion{
		ProtocolVersion: protocol,
		Product:         product,
		Revision:        revision,
		UserAgent:       ua,
		JSVersion:       js,
	}
}

func getNavigatorWebdriver(ctx context.Context) webdriverResult {
	var value bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`navigator.webdriver === true`, &value)); err != nil {
		return webdriverResult{Error: err.Error()}
	}
	return webdriverResult{Value: &value}
}

func writeJSONL(path string, flows []capturedFlow) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	for _, flow := range flows {
		if err := enc.Encode(flow); err != nil {
			return err
		}
	}
	return nil
}

func writeFindings(path string, report findings) error {
	if strings.HasSuffix(strings.ToLower(path), ".md") {
		return os.WriteFile(path, []byte(renderFindingsMarkdown(report)), 0o644)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func renderFindingsMarkdown(report findings) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# CDP Capture Spike Findings\n\n")
	fmt.Fprintf(&b, "- Mode: `%s`\n", report.Mode)
	fmt.Fprintf(&b, "- URL: `%s`\n", report.URL)
	fmt.Fprintf(&b, "- Chrome: `%s`\n", report.Chrome.Product)
	if report.NavigatorWebdrive.Error != "" {
		fmt.Fprintf(&b, "- `navigator.webdriver`: error: `%s`\n", report.NavigatorWebdrive.Error)
	} else if report.NavigatorWebdrive.Value != nil {
		fmt.Fprintf(&b, "- `navigator.webdriver`: `%t`\n", *report.NavigatorWebdrive.Value)
	}
	fmt.Fprintf(&b, "- Requests: `%d`\n", report.Counts.Requests)
	fmt.Fprintf(&b, "- Responses: `%d`\n", report.Counts.Responses)
	fmt.Fprintf(&b, "- Flows written: `%d`\n", report.Counts.FlowsWritten)
	fmt.Fprintf(&b, "- Response bodies captured: `%d`\n", report.Counts.ResponseBodies)
	fmt.Fprintf(&b, "- Body failures: `%d`\n", len(report.BodyFailures))
	fmt.Fprintf(&b, "- WebSocket sent/received: `%d` / `%d`\n", report.Counts.WebSocketSent, report.Counts.WebSocketReceived)
	fmt.Fprintf(&b, "- SSE messages: `%d`\n", report.Counts.EventSource)
	fmt.Fprintf(&b, "\n## Notes\n\n")
	for _, note := range report.Notes {
		fmt.Fprintf(&b, "- %s\n", note)
	}
	if len(report.BodyFailures) > 0 {
		fmt.Fprintf(&b, "\n## Body Failures\n\n")
		for _, failure := range report.BodyFailures {
			fmt.Fprintf(&b, "- `%s` `%s`: %s\n", failure.RequestID, failure.URL, failure.Error)
		}
	}
	return b.String()
}

func phase0Notes(runErr error) []string {
	notes := []string{
		"Compare the JSONL against a Python mitmproxy recon from the same browsing path; raw counts do not need to match if API-candidate coverage is equivalent.",
		"Run the required webdriver matrix separately: remote-debugging-port=0, fixed nonzero port with dedicated user-data-dir, and attach to a user-launched Chrome.",
		"Exercise body retrieval with small JSON, large JSON, binary, cached, service-worker, WebSocket, and SSE targets before the Phase 0 decision gate.",
		"Chrome 136+ may reject remote debugging against the default profile; this spike defaults to a dedicated user-data-dir for launch mode.",
	}
	if runErr != nil {
		notes = append(notes, "Navigation/capture returned error: "+runErr.Error())
	}
	return notes
}

func parseRequestURL(raw string) (string, string, string) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw, "", ""
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return raw, strings.ToLower(parsed.Hostname()), path
}

func headersToStrings(headers network.Headers) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[strings.ToLower(key)] = fmt.Sprint(value)
	}
	return out
}

func base64String(body []byte) *string {
	if len(body) == 0 {
		return nil
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	return &encoded
}

func appendTag(tags []string, tag string) []string {
	for _, existing := range tags {
		if existing == tag {
			return tags
		}
	}
	return append(tags, tag)
}

func sortedTags(tags []string) []string {
	tags = append([]string(nil), tags...)
	sort.Strings(tags)
	return tags
}

func defaultUserDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "apisniff-chrome-profile")
	}
	return filepath.Join(home, ".apisniff", "chrome-profile-phase0")
}

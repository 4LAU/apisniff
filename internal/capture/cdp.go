package capture

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/4LAU/apisniff-go/internal/classify"
	"github.com/4LAU/apisniff-go/internal/model"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type Config struct {
	Domain      string
	URL         string
	Mode        string
	Port        int
	UserDataDir string
	AttachURL   string
	Headless    bool
	Wait        time.Duration
	Timeout     time.Duration
}

type Result struct {
	BundleDir string             `json:"bundle_dir"`
	FlowsPath string             `json:"flows_path"`
	CAPath    string             `json:"ca_path,omitempty"`
	Stats     model.SessionStats `json:"stats"`
}

type partialFlow struct {
	flow model.CapturedFlow
}

type recorder struct {
	mu      sync.Mutex
	flows   map[network.RequestID]*partialFlow
	order   []network.RequestID
	bodyWG  sync.WaitGroup
	dropped map[string]int
}

func Capture(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Mode == "" {
		cfg.Mode = "cdp-launch"
	}
	if cfg.Mode == "proxy" {
		return CaptureProxy(ctx, cfg)
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort()
	}
	if cfg.Wait == 0 {
		cfg.Wait = 5 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.URL == "" {
		cfg.URL = "https://" + cfg.Domain
	}
	start := time.Now()
	bundle, err := NewBundleDir(cfg.Domain, start)
	if err != nil {
		return nil, err
	}
	flowsPath := filepath.Join(bundle, "flows.jsonl")
	writer, err := NewJSONLWriter(flowsPath)
	if err != nil {
		return nil, err
	}

	runCtx, cancelTimeout := context.WithTimeout(ctx, cfg.Timeout)
	defer cancelTimeout()
	browserCtx, cancelBrowser, err := NewBrowserContext(runCtx, cfg.Mode, cfg.Port, cfg.UserDataDir, cfg.AttachURL, cfg.Headless)
	if err != nil {
		return nil, err
	}
	defer cancelBrowser()

	rec := &recorder{flows: map[network.RequestID]*partialFlow{}, dropped: map[string]int{}}
	classifier, err := classify.New(cfg.Domain)
	if err != nil {
		return nil, err
	}
	chromedp.ListenTarget(browserCtx, rec.listen(browserCtx))
	runErr := chromedp.Run(browserCtx,
		network.Enable().
			WithMaxTotalBufferSize(100*1024*1024).
			WithMaxResourceBufferSize(25*1024*1024),
		chromedp.Navigate(cfg.URL),
		chromedp.Sleep(cfg.Wait),
	)
	rec.bodyWG.Wait()
	for _, flow := range rec.snapshotFlows() {
		classification, kept := classifier.Classify(flow)
		if classification.Action == "drop" {
			dropKey := classification.Reason
			if dropKey == "" {
				dropKey = string(classification.Category)
			}
			rec.dropped[dropKey]++
			continue
		}
		if kept == nil {
			continue
		}
		kept.Tags = appendTag(kept.Tags, "category:"+string(classification.Category))
		if err := writer.Write(*kept); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	stats := model.SessionStats{
		Domain:          cfg.Domain,
		StartedAt:       start.UTC().Format(time.RFC3339),
		DurationSeconds: time.Since(start).Seconds(),
		TotalFlows:      len(rec.order),
		KeptFlows:       writer.Count(),
		Dropped:         rec.dropped,
	}
	if err := WriteSession(bundle, stats); err != nil {
		return nil, err
	}
	if runErr != nil && writer.Count() == 0 {
		return nil, runErr
	}
	return &Result{BundleDir: bundle, FlowsPath: flowsPath, Stats: stats}, nil
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
		case *network.EventRequestServedFromCache:
			r.addTag(ev.RequestID, "served_from_cache")
		case *network.EventLoadingFailed:
			r.addTag(ev.RequestID, "loading_failed")
		}
	}
}

func (r *recorder) requestWillBeSent(ctx context.Context, ev *network.EventRequestWillBeSent) {
	rawURL, host, path := parseRequestURL(ev.Request.URL)
	flow := model.NewCapturedFlow(ev.Request.Method, rawURL, host, path)
	flow.RequestHeaders = headersToStrings(ev.Request.Headers)
	r.mu.Lock()
	if _, exists := r.flows[ev.RequestID]; !exists {
		r.order = append(r.order, ev.RequestID)
	}
	r.flows[ev.RequestID] = &partialFlow{flow: flow}
	r.mu.Unlock()
	if ev.Request.HasPostData {
		r.bodyWG.Add(1)
		go func() {
			defer r.bodyWG.Done()
			var body []byte
			err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				body, err = network.GetRequestPostData(ev.RequestID).Do(ctx)
				return err
			}))
			if err != nil {
				r.addTag(ev.RequestID, "request_body_error")
				return
			}
			r.mu.Lock()
			if pf := r.flows[ev.RequestID]; pf != nil {
				pf.flow.RequestBody = body
			}
			r.mu.Unlock()
		}()
	}
}

func (r *recorder) responseReceived(ev *network.EventResponseReceived) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pf := r.ensureFlowLocked(ev.RequestID, ev.Response.URL)
	pf.flow.ResponseStatus = int(ev.Response.Status)
	pf.flow.ResponseHeaders = headersToStrings(ev.Response.Headers)
	if ev.Response.FromDiskCache {
		pf.flow.Tags = appendTag(pf.flow.Tags, "served_from_cache")
	}
	if ev.Response.FromServiceWorker {
		pf.flow.Tags = appendTag(pf.flow.Tags, "service_worker")
	}
	if ev.Type.String() != "" {
		pf.flow.Tags = appendTag(pf.flow.Tags, "resource_type:"+ev.Type.String())
	}
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
		if err != nil {
			r.addTag(ev.RequestID, "response_body_error")
			return
		}
		r.mu.Lock()
		if pf := r.flows[ev.RequestID]; pf != nil {
			pf.flow.ResponseBody = body
		}
		r.mu.Unlock()
	}()
}

func (r *recorder) addTag(id network.RequestID, tag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pf := r.ensureFlowLocked(id, "")
	pf.flow.Tags = appendTag(pf.flow.Tags, tag)
}

func (r *recorder) ensureFlowLocked(id network.RequestID, rawURL string) *partialFlow {
	if pf := r.flows[id]; pf != nil {
		return pf
	}
	reqURL, host, path := parseRequestURL(rawURL)
	flow := model.NewCapturedFlow("", reqURL, host, path)
	flow.Tags = appendTag(flow.Tags, "missing_request_event")
	pf := &partialFlow{flow: flow}
	r.flows[id] = pf
	r.order = append(r.order, id)
	return pf
}

func (r *recorder) snapshotFlows() []model.CapturedFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	flows := make([]model.CapturedFlow, 0, len(r.order))
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
		out[strings.ToLower(key)] = stringifyHeader(value)
	}
	return out
}

func stringifyHeader(value any) string {
	return fmt.Sprint(value)
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

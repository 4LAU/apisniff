package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/vendor"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

type Config struct {
	Domain        string
	URL           string
	Mode          string
	Port          int
	UserDataDir   string
	AttachURL     string
	Headless      bool
	LaunchBrowser bool
	Timeout       time.Duration
	StatusWriter  io.Writer
}

type Result struct {
	BundleDir    string             `json:"bundle_dir"`
	FlowsPath    string             `json:"flows_path"`
	FilteredPath string             `json:"filtered_path,omitempty"`
	CAPath       string             `json:"ca_path,omitempty"`
	SPKIHash     string             `json:"spki_hash,omitempty"`
	Stats        model.SessionStats `json:"stats"`
}

type partialFlow struct {
	flow       model.CapturedFlow
	wsFrames   []webSocketFrameCapture
	wsSent     int
	wsReceived int
	wsErrors   int
}

type recorder struct {
	mu        sync.Mutex
	flows     map[network.RequestID]*partialFlow
	order     []network.RequestID
	bodyWG    sync.WaitGroup
	dropped   map[string]int
	flowCount atomic.Int64
}

type webSocketFrameCapture struct {
	Direction string  `json:"direction"`
	Opcode    float64 `json:"opcode"`
	Payload   string  `json:"payload"`
	Truncated bool    `json:"truncated,omitempty"`
}

const (
	maxWebSocketFrames       = 100
	maxWebSocketFramePayload = 64 * 1024
)

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
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Minute
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
	writerClosed := false
	defer func() {
		if !writerClosed {
			_ = writer.Close()
		}
	}()

	signalCtx, stopSignals := signal.NotifyContext(ctx, gracefulSignals...)
	defer stopSignals()
	runCtx, cancelTimeout := context.WithTimeout(signalCtx, cfg.Timeout)
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
	// Fail-soft: a signature-load failure must never abort capture.
	det, err := vendor.NewDetector()
	if err != nil {
		if cfg.StatusWriter != nil {
			fmt.Fprintf(cfg.StatusWriter, "defense detection disabled: %v\n", err)
		}
		det = nil
	}
	targetRD := classify.ExtractRegisteredDomain(cfg.Domain)
	defenses := map[string]model.VendorMatch{}
	var unattributedAntibot int

	showStatus := cfg.StatusWriter != nil && isTerminal(cfg.StatusWriter)
	var status *statusLine
	if showStatus {
		status = newStatusLine(cfg.StatusWriter, "Capturing traffic", &rec.flowCount)
		status.start()
	}

	chromedp.ListenTarget(browserCtx, rec.listen(browserCtx))
	runErr := chromedp.Run(browserCtx,
		network.Enable().
			WithMaxTotalBufferSize(100*1024*1024).
			WithMaxResourceBufferSize(25*1024*1024),
		chromedp.Navigate(cfg.URL),
	)
	if runErr == nil {
		tabClosed := make(chan struct{}, 1)
		signalClose := func() {
			select {
			case tabClosed <- struct{}{}:
			default:
			}
		}
		go func() {
			<-browserCtx.Done()
			signalClose()
		}()
		if cfg.Mode == "cdp-launch" {
			go func() {
				c := chromedp.FromContext(browserCtx)
				if c == nil || c.Browser == nil {
					return
				}
				consecutiveEmptyOrError := 0
				ticker := time.NewTicker(500 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-runCtx.Done():
						return
					case <-ticker.C:
						pollCtx, pollCancel := context.WithTimeout(runCtx, 2*time.Second)
						pollExec := cdp.WithExecutor(pollCtx, c.Browser)
						infos, err := target.GetTargets().Do(pollExec)
						pollCancel()
						if err != nil {
							consecutiveEmptyOrError++
							if consecutiveEmptyOrError >= 3 {
								signalClose()
								return
							}
							continue
						}
						pages := 0
						for _, info := range infos {
							if info.Type == "page" && !strings.HasPrefix(info.URL, "chrome://") {
								pages++
							}
						}
						if pages == 0 {
							consecutiveEmptyOrError++
							if consecutiveEmptyOrError >= 3 {
								signalClose()
								return
							}
						} else {
							consecutiveEmptyOrError = 0
						}
					}
				}
			}()
		}
		select {
		case <-tabClosed:
		case <-runCtx.Done():
		}
	}
	cancelBrowser()
	if status != nil {
		status.stop()
	}
	rec.bodyWG.Wait()
	filtered := newLazyFilteredWriter(bundle)
	defer filtered.Close()
	snapshot := rec.snapshotFlows()
	// Classification happens post-capture here, so the two-pass Learn makes
	// the result independent of event arrival order.
	for _, flow := range snapshot {
		classifier.Learn(flow)
	}
	for _, flow := range snapshot {
		classification, kept := classifier.Classify(flow)
		matches, scoped := detectDefenses(det, targetRD, flow, classification)
		mergeDefenses(defenses, matches)
		if scoped && isAntibot(classification) && len(matches) == 0 {
			unattributedAntibot++
		}
		if classification.Action == "drop" {
			dropKey := classification.Reason
			if dropKey == "" {
				dropKey = string(classification.Category)
			}
			rec.dropped[dropKey]++
			filtered.Write(flow, classification)
			continue
		}
		if kept == nil {
			continue
		}
		if err := writer.Write(*kept); err != nil {
			return nil, err
		}
	}
	resultFilteredPath := filtered.Close()
	writerClosed = true
	if err := writer.Close(); err != nil {
		return nil, err
	}
	stats := model.SessionStats{
		Domain:              cfg.Domain,
		StartedAt:           start.UTC().Format(time.RFC3339),
		DurationSeconds:     time.Since(start).Seconds(),
		TotalFlows:          len(rec.order),
		KeptFlows:           writer.Count(),
		Dropped:             rec.dropped,
		Defenses:            sortedDefenses(defenses),
		UnattributedAntibot: unattributedAntibot,
	}
	if err := WriteSession(bundle, stats); err != nil {
		return nil, err
	}
	if runErr != nil && writer.Count() == 0 {
		return nil, runErr
	}
	return &Result{BundleDir: bundle, FlowsPath: flowsPath, FilteredPath: resultFilteredPath, Stats: stats}, nil
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
		case *network.EventWebSocketCreated:
			r.webSocketCreated(ev)
		case *network.EventWebSocketWillSendHandshakeRequest:
			r.webSocketWillSendHandshakeRequest(ev)
		case *network.EventWebSocketHandshakeResponseReceived:
			r.webSocketHandshakeResponseReceived(ev)
		case *network.EventWebSocketFrameSent:
			r.webSocketFrame(ev.RequestID, "sent", ev.Response)
		case *network.EventWebSocketFrameReceived:
			r.webSocketFrame(ev.RequestID, "received", ev.Response)
		case *network.EventWebSocketFrameError:
			r.webSocketFrameError(ev)
		case *network.EventWebSocketClosed:
			r.addTag(ev.RequestID, "websocket_closed")
		}
	}
}

func (r *recorder) requestWillBeSent(ctx context.Context, ev *network.EventRequestWillBeSent) {
	rawURL, host, path := parseRequestURL(ev.Request.URL)
	flow := model.NewCapturedFlow(ev.Request.Method, rawURL, host, path)
	flow.RequestHeaders = headersToStrings(ev.Request.Headers)
	r.mu.Lock()
	if existing, ok := r.flows[ev.RequestID]; ok && ev.RedirectResponse != nil {
		existing.flow.ResponseStatus = int(ev.RedirectResponse.Status)
		existing.flow.ResponseHeaders = headersToStrings(ev.RedirectResponse.Headers)
		existing.flow.Tags = appendTag(existing.flow.Tags, "redirected")
		redirectID := network.RequestID(fmt.Sprintf("%s.r%d", ev.RequestID, len(r.order)))
		r.flows[redirectID] = existing
		r.order = append(r.order, redirectID)
	} else if !ok {
		r.order = append(r.order, ev.RequestID)
		r.flowCount.Add(1)
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
	if ev.Response.Protocol != "" {
		pf.flow.Tags = appendTag(pf.flow.Tags, "protocol:"+ev.Response.Protocol)
	}
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
		r.addTag(ev.RequestID, "response_encoded_bytes:"+strconv.FormatInt(int64(ev.EncodedDataLength), 10))
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
			pf.flow.Tags = appendTag(pf.flow.Tags, "response_body_bytes:"+strconv.Itoa(len(body)))
		}
		r.mu.Unlock()
	}()
}

func (r *recorder) webSocketCreated(ev *network.EventWebSocketCreated) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pf := r.ensureFlowLocked(ev.RequestID, ev.URL)
	if pf.flow.Method == "" {
		pf.flow.Method = "GET"
	}
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket")
}

func (r *recorder) webSocketWillSendHandshakeRequest(ev *network.EventWebSocketWillSendHandshakeRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pf := r.ensureFlowLocked(ev.RequestID, "")
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket")
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket_handshake_request")
	if ev.Request != nil && len(ev.Request.Headers) > 0 {
		pf.flow.RequestHeaders = headersToStrings(ev.Request.Headers)
	}
}

func (r *recorder) webSocketHandshakeResponseReceived(ev *network.EventWebSocketHandshakeResponseReceived) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pf := r.ensureFlowLocked(ev.RequestID, "")
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket")
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket_handshake_response")
	if ev.Response != nil {
		pf.flow.ResponseStatus = int(ev.Response.Status)
		pf.flow.ResponseHeaders = headersToStrings(ev.Response.Headers)
	}
}

func (r *recorder) webSocketFrame(id network.RequestID, direction string, frame *network.WebSocketFrame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pf := r.ensureFlowLocked(id, "")
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket")
	if direction == "sent" {
		pf.wsSent++
	} else {
		pf.wsReceived++
	}
	if frame == nil || len(pf.wsFrames) >= maxWebSocketFrames {
		return
	}
	payload := frame.PayloadData
	truncated := false
	if len(payload) > maxWebSocketFramePayload {
		payload = payload[:maxWebSocketFramePayload]
		truncated = true
	}
	pf.wsFrames = append(pf.wsFrames, webSocketFrameCapture{
		Direction: direction,
		Opcode:    frame.Opcode,
		Payload:   payload,
		Truncated: truncated,
	})
}

func (r *recorder) webSocketFrameError(ev *network.EventWebSocketFrameError) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pf := r.ensureFlowLocked(ev.RequestID, "")
	pf.wsErrors++
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket")
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket_frame_error")
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
		pf.finalizeWebSocket()
		pf.flow.Tags = sortedTags(pf.flow.Tags)
		flows = append(flows, pf.flow)
	}
	return flows
}

func (pf *partialFlow) finalizeWebSocket() {
	if pf.wsSent == 0 && pf.wsReceived == 0 && pf.wsErrors == 0 {
		return
	}
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket_sent_frames:"+strconv.Itoa(pf.wsSent))
	pf.flow.Tags = appendTag(pf.flow.Tags, "websocket_received_frames:"+strconv.Itoa(pf.wsReceived))
	if pf.wsErrors > 0 {
		pf.flow.Tags = appendTag(pf.flow.Tags, "websocket_frame_errors:"+strconv.Itoa(pf.wsErrors))
	}
	if len(pf.wsFrames) == 0 || len(pf.flow.ResponseBody) > 0 {
		return
	}
	body, err := json.Marshal(map[string]any{"websocket_frames": pf.wsFrames})
	if err == nil {
		pf.flow.ResponseBody = body
		if pf.flow.ResponseHeaders == nil {
			pf.flow.ResponseHeaders = map[string]string{}
		}
		pf.flow.ResponseHeaders["content-type"] = "application/json"
	}
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

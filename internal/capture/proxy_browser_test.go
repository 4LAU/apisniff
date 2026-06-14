//go:build apisniff_chrome

package capture

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/adapter"
)

func TestProxyBrowserSPKIBypass(t *testing.T) {
	skipUnlessChrome(t)
	setTestHome(t, t.TempDir())

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		result *Result
		err    error
	}
	ch := make(chan outcome, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{
			Domain:        "127.0.0.1",
			Port:          port,
			LaunchBrowser: true,
			Headless:      true,
			URL:           backend.URL,
			Timeout:       30 * time.Second,
		})
		ch <- outcome{result, err}
	}()

	// Give Chrome time to start and load the page through the proxy. The
	// clean-launch path uses a fresh on-disk profile and headless=new, which
	// cold-starts slower than the old chromedp temp-profile launch.
	time.Sleep(20 * time.Second)
	cancel()

	var res outcome
	select {
	case res = <-ch:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for CaptureProxy to return")
	}
	if res.err != nil {
		t.Fatalf("CaptureProxy error: %v", res.err)
	}
	result := res.result

	if result.SPKIHash == "" {
		t.Fatal("SPKIHash is empty — SPKI bypass chain not established")
	}
	if result.CAPath == "" {
		t.Fatal("CAPath is empty")
	}
	if _, err := os.Stat(result.CAPath); err != nil {
		t.Fatalf("CA cert file missing at %s: %v", result.CAPath, err)
	}

	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatalf("LoadJSONL: %v", err)
	}
	if len(flows) < 1 {
		t.Fatal("no flows captured — Chrome did not connect through the MITM proxy")
	}

	// At least one flow should target the test server. flow.Host carries the
	// hostname without the port, so compare against the host part only.
	wantHostPort := strings.TrimPrefix(strings.TrimPrefix(backend.URL, "https://"), "http://")
	wantHost := wantHostPort
	if h, _, err := net.SplitHostPort(wantHostPort); err == nil {
		wantHost = h
	}
	found := false
	for _, f := range flows {
		if f.Host == wantHost || f.Host == wantHostPort {
			found = true
			break
		}
	}
	if !found {
		hosts := make([]string, len(flows))
		for i, f := range flows {
			hosts[i] = f.Host
		}
		t.Fatalf("no flow targets test server host %s: %v", wantHost, hosts)
	}
}

func TestProxyBrowserDrainOnShutdown(t *testing.T) {
	skipUnlessChrome(t)
	setTestHome(t, t.TempDir())

	// release controls when the server finishes its slow response.
	release := make(chan struct{})
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		// First chunk: flush immediately.
		w.Write([]byte(`{"chunk":1}` + "\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Block until released or request cancelled.
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.Write([]byte(`{"chunk":2}` + "\n"))
	}))
	defer backend.Close()
	defer func() {
		// Ensure server handler is unblocked on test exit.
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		result *Result
		err    error
	}
	ch := make(chan outcome, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{
			Domain:        "127.0.0.1",
			Port:          port,
			LaunchBrowser: true,
			Headless:      true,
			URL:           backend.URL,
			Timeout:       30 * time.Second,
		})
		ch <- outcome{result, err}
	}()

	// Wait for Chrome to start and begin loading the slow response. The
	// clean-launch path cold-starts a fresh on-disk profile, so allow more time.
	time.Sleep(20 * time.Second)

	// Cancel the context while the response is still in-flight (chunked
	// transfer is blocked on the release channel).
	cancel()

	// Let the server finish if it hasn't already been disconnected.
	select {
	case <-release:
	default:
		close(release)
	}

	var res outcome
	select {
	case res = <-ch:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for CaptureProxy to return")
	}
	if res.err != nil {
		t.Fatalf("CaptureProxy error: %v", res.err)
	}
	result := res.result

	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatalf("LoadJSONL: %v", err)
	}
	if len(flows) < 1 {
		t.Fatal("no flows captured — drain period did not preserve the in-flight request")
	}

	// The slow response was interrupted mid-stream. Depending on timing the
	// flow may carry an incomplete or error tag.
	drainedFlow := flows[0]

	// Log what we got for debugging.
	t.Logf("flow path=%s tags=%v body_len=%d", drainedFlow.Path, drainedFlow.Tags, len(drainedFlow.ResponseBody))

	// The first chunk must have been captured — the response body should not
	// be completely empty.
	if len(drainedFlow.ResponseBody) == 0 {
		t.Fatal("response body is empty — drain period failed to capture partial response")
	}

	// Chrome disconnected mid-stream, so the flow should carry an incomplete
	// or error tag. However, if the full response completed before Chrome
	// disconnected (race), both chunks will be present and neither tag will
	// appear — that is acceptable too.
	hasIncompleteOrError := hasTag(drainedFlow.Tags, "response_body_incomplete") || hasTag(drainedFlow.Tags, "response_body_error") || hasTag(drainedFlow.Tags, "response_body_truncated")
	bodyHasBothChunks := strings.Contains(string(drainedFlow.ResponseBody), `"chunk":1`) && strings.Contains(string(drainedFlow.ResponseBody), `"chunk":2`)
	if !hasIncompleteOrError && !bodyHasBothChunks {
		t.Fatalf("expected incomplete/error tag or full body; got tags=%v body=%q",
			drainedFlow.Tags, fmt.Sprintf("%.200s", drainedFlow.ResponseBody))
	}
}

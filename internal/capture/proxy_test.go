package capture

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/adapter"
)

func TestCaptureProxyCapturesHTTPFlow(t *testing.T) {
	setTestHome(t, t.TempDir())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/data" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL + "/api/data?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	if result.CAPath == "" {
		t.Fatalf("missing CA path")
	}
	if _, err := os.Stat(result.CAPath); err != nil {
		t.Fatalf("CA cert missing: %v", err)
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	if flows[0].Method != "GET" || flows[0].Path != "/api/data?x=1" || flows[0].ResponseStatus != 200 {
		t.Fatalf("flow = %#v", flows[0])
	}
	sessionData, err := os.ReadFile(filepath.Join(result.BundleDir, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stats map[string]any
	if err := json.Unmarshal(sessionData, &stats); err != nil {
		t.Fatal(err)
	}
	if stats["kept_flows"].(float64) != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestCaptureProxyCapturesHTTPSMITMFlow(t *testing.T) {
	setTestHome(t, t.TempDir())
	caPath, err := EnsureProxyCA()
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load proxy CA")
	}
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"secure":true}`))
	}))
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots}, //nolint:gosec
	}}
	resp, err := client.Get(backend.URL + "/api/secure")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || flows[0].Path != "/api/secure" || flows[0].ResponseStatus != 200 {
		t.Fatalf("flows = %#v", flows)
	}
}

func TestCaptureProxyUsesHTTP2UpstreamWhenAvailable(t *testing.T) {
	setTestHome(t, t.TempDir())
	caPath, err := EnsureProxyCA()
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load proxy CA")
	}

	protoCh := make(chan string, 1)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case protoCh <- r.Proto:
		default:
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"h2":true}`))
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: roots}, //nolint:gosec
	}}
	resp, err := client.Get(backend.URL + "/api/h2")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	select {
	case proto := <-protoCh:
		if proto != "HTTP/2.0" {
			t.Fatalf("upstream proto = %s, want HTTP/2.0", proto)
		}
	default:
		t.Fatal("backend did not receive proxied request")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || !hasTag(flows[0].Tags, "upstream_response_proto:HTTP/2.0") {
		t.Fatalf("flows = %#v", flows)
	}
}

func TestFinalizingBodyCapturesPrefixAndForwardsFully(t *testing.T) {
	var gotBody []byte
	var gotTruncated, gotComplete bool
	var fires int
	body := newFinalizingBody(io.NopCloser(strings.NewReader("abcdef")), 3, func(body []byte, truncated, complete bool, readErr error) {
		fires++
		gotBody, gotTruncated, gotComplete = body, truncated, complete
		if readErr != nil {
			t.Errorf("readErr = %v", readErr)
		}
	})
	forwarded, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if string(forwarded) != "abcdef" {
		t.Fatalf("forwarded = %q, want full body", forwarded)
	}
	if string(gotBody) != "abc" || !gotTruncated || !gotComplete || fires != 1 {
		t.Fatalf("captured=%q truncated=%v complete=%v fires=%d", gotBody, gotTruncated, gotComplete, fires)
	}
}

func TestFinalizingBodyCloseWithoutEOFReportsIncomplete(t *testing.T) {
	var gotComplete bool
	var fires int
	body := newFinalizingBody(io.NopCloser(strings.NewReader("abcdef")), 100, func(body []byte, truncated, complete bool, readErr error) {
		fires++
		gotComplete = complete
	})
	buf := make([]byte, 2)
	if _, err := body.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if gotComplete || fires != 1 {
		t.Fatalf("complete=%v fires=%d, want incomplete single fire", gotComplete, fires)
	}
}

func TestCaptureProxyStreamsResponseBeforeCompletion(t *testing.T) {
	// Streaming matters on the MITM (CONNECT/hijack) path, which is how all
	// HTTPS browser traffic flows; goproxy writes it straight to the client
	// connection. The plain-HTTP proxy path buffers inside net/http and is
	// not exercised here.
	setTestHome(t, t.TempDir())
	caPath, err := EnsureProxyCA()
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load proxy CA")
	}
	release := make(chan struct{})
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"chunk":1}` + "\n"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte(`{"chunk":2}` + "\n"))
	}))
	defer backend.Close()
	defer close(release)

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots}, //nolint:gosec
	}}
	resp, err := client.Get(backend.URL + "/api/stream")
	if err != nil {
		t.Fatal(err)
	}
	// The first chunk must arrive while the server is still holding the
	// stream open — the old design buffered the whole body first.
	firstChunk := make(chan error, 1)
	buf := make([]byte, 64)
	go func() {
		_, readErr := resp.Body.Read(buf)
		firstChunk <- readErr
	}()
	select {
	case err := <-firstChunk:
		if err != nil {
			t.Fatalf("first chunk read failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy buffered the streaming response instead of passing it through")
	}
	release <- struct{}{}
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(string(buf)+string(rest), `{"chunk":2}`) {
		t.Fatalf("stream tail missing: %q", string(buf)+string(rest))
	}
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || !strings.Contains(string(flows[0].ResponseBody), `{"chunk":2}`) {
		t.Fatalf("flows = %#v", flows)
	}
}

func TestCaptureProxyTruncatesCapturedBodyAtCapAndForwardsFully(t *testing.T) {
	setTestHome(t, t.TempDir())
	const bodySize = proxyBodyLimit + 512*1024
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := bytes.Repeat([]byte("x"), 64*1024)
		written := 0
		for written < bodySize {
			n := bodySize - written
			if n > len(chunk) {
				n = len(chunk)
			}
			w.Write(chunk[:n])
			written += n
		}
	}))
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL + "/api/big")
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if forwarded != bodySize {
		t.Fatalf("client received %d bytes, want %d", forwarded, bodySize)
	}
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	if len(flows[0].ResponseBody) != proxyBodyLimit {
		t.Fatalf("captured body = %d bytes, want cap %d", len(flows[0].ResponseBody), proxyBodyLimit)
	}
	if !hasTag(flows[0].Tags, "response_body_truncated") {
		t.Fatalf("missing truncation tag: %v", flows[0].Tags)
	}
}

func TestCaptureProxyTagsRequestBodyIncompleteWhenUpstreamRespondsEarly(t *testing.T) {
	setTestHome(t, t.TempDir())
	// Larger than net/http's post-handler drain limit (256KB) so the backend
	// closes the connection without ever consuming the full upload.
	const bodySize = 4 * 1024 * 1024
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond immediately without reading the request body.
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		w.Write([]byte(`{"error":"too large"}`))
	}))
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Post(backend.URL+"/api/upload", "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte("y"), bodySize)))
	// The early response can surface as an error mid-upload depending on
	// timing; the flow finalizes either way once the proxy finishes copying
	// the (tiny) response body.
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	time.Sleep(300 * time.Millisecond)
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	if !hasTag(flows[0].Tags, "request_body_incomplete") {
		t.Fatalf("partial upload missing request_body_incomplete tag: %v", flows[0].Tags)
	}
	if hasTag(flows[0].Tags, "request_body_truncated") {
		t.Fatalf("under-cap upload must not be tagged truncated: %v", flows[0].Tags)
	}
	if len(flows[0].RequestBody) >= bodySize {
		t.Fatalf("captured %d bytes, expected a partial prefix of %d", len(flows[0].RequestBody), bodySize)
	}
}

func TestCaptureProxyRecordsFlowWhenClientAborts(t *testing.T) {
	setTestHome(t, t.TempDir())
	handlerDone := make(chan struct{}, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { handlerDone <- struct{}{} }()
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := []byte(`{"tick":true}` + "\n")
		for i := 0; i < 4000; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}))
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL + "/api/endless")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The proxy closes the upstream body before finalizing, so once the
	// backend has observed the abort, finalization is imminent; the short
	// grace covers the classify+write that follows.
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never observed client abort")
	}
	time.Sleep(300 * time.Millisecond)
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("aborted stream was not recorded: flows = %d", len(flows))
	}
	if !hasTag(flows[0].Tags, "response_body_incomplete") && !hasTag(flows[0].Tags, "response_body_error") {
		t.Fatalf("aborted stream missing incomplete/error tag: %v", flows[0].Tags)
	}
}

func TestCaptureProxyConcurrentRequestsRecordAllFlows(t *testing.T) {
	setTestHome(t, t.TempDir())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"i":"` + r.URL.Query().Get("i") + `"}`))
	}))
	defer backend.Close()

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: port, Timeout: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	waitForProxy(t, port)

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	const n = 24
	var wg sync.WaitGroup
	reqErrs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Get(backend.URL + "/api/data?i=" + strconv.Itoa(i))
			if err != nil {
				reqErrs[i] = err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
	for i, err := range reqErrs {
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}
	cancel()

	var result *Result
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for proxy capture")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != n {
		t.Fatalf("flows = %d, want %d (concurrent flows lost)", len(flows), n)
	}
	seen := map[string]bool{}
	for _, flow := range flows {
		seen[flow.Path] = true
		if got := `{"i":"` + strings.TrimPrefix(flow.Path, "/api/data?i=") + `"}`; string(flow.ResponseBody) != got {
			t.Fatalf("flow %s carries wrong body %q (cross-request corruption)", flow.Path, flow.ResponseBody)
		}
	}
	if len(seen) != n {
		t.Fatalf("distinct paths = %d, want %d", len(seen), n)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForProxy(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proxy did not listen on port %d", port)
}

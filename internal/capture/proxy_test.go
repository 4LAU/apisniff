package capture

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
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
	caPath, _, err := EnsureProxyCA(nil)
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
	caPath, _, err := EnsureProxyCA(nil)
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
	caPath, _, err := EnsureProxyCA(nil)
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
	// Release keep-alive connections so shutdown drains deterministically on
	// slow CI runners.
	client.CloseIdleConnections()
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

func TestCaptureProxyNoBrowserDefaultsTo8080(t *testing.T) {
	setTestHome(t, t.TempDir())
	// Occupy 8080; a no-browser, port-omitted call must TRY 8080 (and thus
	// fail to bind), proving the !LaunchBrowser default is preserved.
	blocker, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("cannot occupy 127.0.0.1:8080 (in use): %v", err)
	}
	defer blocker.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = CaptureProxy(ctx, Config{Domain: "127.0.0.1", Port: 0, LaunchBrowser: false})
	if err == nil {
		t.Fatal("no-browser Port:0 should default to 8080 and fail to bind (8080 occupied)")
	}
}

func TestCaptureProxyPreservesCookieHeaders(t *testing.T) {
	setTestHome(t, t.TempDir())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc; Path=/")
		w.Header().Add("Set-Cookie", "csrf=xyz; Path=/")
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
	req, err := http.NewRequest("GET", backend.URL+"/api/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "session=abc")
	resp, err := client.Do(req)
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
		t.Fatal("timed out")
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	if got := flows[0].RequestHeaders["cookie"]; got != "session=abc" {
		t.Errorf("request cookie = %q, want session=abc", got)
	}
	// Two Set-Cookie values, joined with \n per headersToMap.
	if got := flows[0].ResponseHeaders["set-cookie"]; got != "session=abc; Path=/\ncsrf=xyz; Path=/" {
		t.Errorf("response set-cookie = %q", got)
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

func TestGenerateProxyCAUsesECDSA(t *testing.T) {
	_, _, cert, err := generateProxyCA()
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P-256", ecKey.Curve)
	}
	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("cert.Leaf is nil")
	}
	if !leaf.IsCA {
		t.Fatal("cert is not a CA")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("public key curve = %v, want P-256", pub.Curve)
	}
}

func TestSPKIHashDeterministic(t *testing.T) {
	_, _, cert, err := generateProxyCA()
	if err != nil {
		t.Fatal(err)
	}
	h1 := SPKIHash(cert.Leaf)
	h2 := SPKIHash(cert.Leaf)
	if h1 == "" {
		t.Fatal("SPKIHash returned empty string")
	}
	if h1 != h2 {
		t.Fatalf("SPKIHash not deterministic: %q != %q", h1, h2)
	}
	if _, err := base64.StdEncoding.DecodeString(h1); err != nil {
		t.Fatalf("SPKIHash is not valid base64: %v", err)
	}
}

func TestSPKIHashWorksForRSAAndECDSA(t *testing.T) {
	makeRSACert := func(t *testing.T) *x509.Certificate {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "test-rsa"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	makeECDSACert := func(t *testing.T) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "test-ecdsa"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	for _, tc := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"RSA", makeRSACert(t)},
		{"ECDSA", makeECDSACert(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := SPKIHash(tc.cert)
			if h == "" {
				t.Fatal("SPKIHash returned empty string")
			}
			if _, err := base64.StdEncoding.DecodeString(h); err != nil {
				t.Fatalf("SPKIHash is not valid base64: %v", err)
			}
		})
	}
}

func TestCertCacheFetchCachesAndDeduplicates(t *testing.T) {
	calls := 0
	fakeCert := &tls.Certificate{}
	gen := func() (*tls.Certificate, error) {
		calls++
		return fakeCert, nil
	}

	c := &certCache{}
	c1, err := c.Fetch("example.com", gen)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := c.Fetch("example.com", gen)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("gen called %d times, want 1", calls)
	}
	if c1 != c2 {
		t.Fatal("Fetch returned different cert pointers for same hostname")
	}
	if c1 != fakeCert {
		t.Fatal("Fetch returned unexpected cert")
	}
}

func TestEnsureProxyCAValidatesExistingCert(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, dir)

	// Write an expired, non-CA cert to the config dir.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "expired"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired
		BasicConstraintsValid: true,
		IsCA:                  false, // not a CA
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	configDir := filepath.Join(dir, ".apisniff")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(configDir, "ca-cert.pem")
	keyPath := filepath.Join(configDir, "ca-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// EnsureProxyCA must detect the invalid cert and regenerate.
	gotPath, spkiHash, err := EnsureProxyCA(nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath == "" {
		t.Fatal("expected non-empty cert path")
	}
	if spkiHash == "" {
		t.Fatal("expected non-empty SPKI hash")
	}
	if _, decErr := base64.StdEncoding.DecodeString(spkiHash); decErr != nil {
		t.Fatalf("SPKI hash is not valid base64: %v", decErr)
	}

	// The regenerated cert must actually be a valid CA.
	newCertPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(newCertPEM) {
		t.Fatal("regenerated cert PEM could not be parsed")
	}
}

// writeInvalidButLoadableCA writes a parseable cert/key pair into the config dir
// that loads via tls.X509KeyPair but fails validateCA (expired, non-CA), forcing
// EnsureProxyCA down the regenerate branch that previously logged via log.Printf.
func writeInvalidButLoadableCA(t *testing.T, home string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "expired"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired
		BasicConstraintsValid: true,
		IsCA:                  false, // not a CA
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	configDir := filepath.Join(home, ".apisniff")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "ca-cert.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "ca-key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureProxyCANilStatusSilentOnRegen(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	writeInvalidButLoadableCA(t, home)
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if _, _, err := EnsureProxyCA(nil); err != nil {
		t.Fatalf("EnsureProxyCA(nil) returned error: %v", err)
	}
	if logBuf.Len() != 0 {
		t.Fatalf("EnsureProxyCA(nil) leaked to the global logger: %q", logBuf.String())
	}
}

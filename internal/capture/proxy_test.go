package capture

import (
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
	"testing"
	"time"

	"github.com/4LAU/apisniff-go/internal/adapter"
)

func TestCaptureProxyCapturesHTTPFlow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
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
	t.Setenv("HOME", t.TempDir())
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
	t.Setenv("HOME", t.TempDir())
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

func TestCaptureBodyForReplayDoesNotTruncateForwardedBody(t *testing.T) {
	captured, replayBody, truncated, err := captureBodyForReplay(io.NopCloser(strings.NewReader("abcdef")), 3)
	if err != nil {
		t.Fatal(err)
	}
	forwarded, readErr := io.ReadAll(replayBody)
	closeErr := replayBody.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if string(captured) != "abc" || string(forwarded) != "abcdef" || !truncated {
		t.Fatalf("captured=%q forwarded=%q truncated=%v", captured, forwarded, truncated)
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

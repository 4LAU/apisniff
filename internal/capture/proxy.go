package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/elazarl/goproxy"
)

const proxyBodyLimit = 5 * 1024 * 1024

type proxyRequestState struct {
	flow    model.CapturedFlow
	reqBody *captureReader
}

func CaptureProxy(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Minute
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
	filtered := newLazyFilteredWriter(bundle)
	defer filtered.Close()

	caPath, err := EnsureProxyCA()
	if err != nil {
		return nil, err
	}
	classifier, err := classify.New(cfg.Domain)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var flowCount atomic.Int64
	stats := model.SessionStats{
		Domain:    cfg.Domain,
		StartedAt: start.UTC().Format(time.RFC3339),
		Dropped:   map[string]int{},
	}
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.AllowHTTP2 = true
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	recordFlow := func(flow model.CapturedFlow) {
		classification, kept := classifier.Classify(flow)
		mu.Lock()
		defer mu.Unlock()
		stats.TotalFlows++
		flowCount.Add(1)
		if classification.Action == "drop" || kept == nil {
			dropKey := classification.Reason
			if dropKey == "" {
				dropKey = string(classification.Category)
			}
			stats.Dropped[dropKey]++
			if classification.Action == "drop" {
				filtered.Write(flow, classification)
			}
			return
		}
		if err := writer.Write(*kept); err != nil {
			stats.Dropped["write_error"]++
			return
		}
		stats.KeptFlows = writer.Count()
	}

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, pctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		flow, err := flowFromProxyRequest(req)
		if err != nil {
			pctx.UserData = err
			return req, nil
		}
		state := &proxyRequestState{flow: flow}
		if req.Body != nil && req.Body != http.NoBody {
			// Record the request body as the transport streams it upstream —
			// no pre-read, no temp file. The snapshot is taken when the
			// response body finishes.
			state.reqBody = newCaptureReader(req.Body, proxyBodyLimit)
			req.Body = state.reqBody
		}
		pctx.UserData = state
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, pctx *goproxy.ProxyCtx) *http.Response {
		state, ok := pctx.UserData.(*proxyRequestState)
		if !ok || resp == nil {
			return resp
		}
		flow := state.flow
		flow.ResponseStatus = resp.StatusCode
		flow.ResponseHeaders = headersToMap(resp.Header)
		flow.Tags = appendTag(flow.Tags, "request_proto:"+flowProto(pctx.Req))
		flow.Tags = appendTag(flow.Tags, "upstream_response_proto:"+resp.Proto)
		reqBody := state.reqBody
		finalize := func(body []byte, truncated, complete bool, readErr error) {
			if reqBody != nil {
				captured, reqTruncated, _, reqErr := reqBody.snapshot()
				if reqErr != nil {
					flow.Tags = appendTag(flow.Tags, "request_body_error")
				} else {
					flow.RequestBody = captured
					if reqTruncated {
						flow.Tags = appendTag(flow.Tags, "request_body_truncated")
					}
				}
			}
			if readErr != nil {
				flow.Tags = appendTag(flow.Tags, "response_body_error")
			} else {
				flow.ResponseBody = body
				if truncated {
					flow.Tags = appendTag(flow.Tags, "response_body_truncated")
				}
				if !complete {
					flow.Tags = appendTag(flow.Tags, "response_body_incomplete")
				}
			}
			recordFlow(flow)
		}
		if resp.Body == nil {
			finalize(nil, false, true, nil)
			return resp
		}
		// The body streams through to the client unbuffered; the flow is
		// recorded once the body completes (EOF) or the client goes away
		// (Close). A streaming/SSE response therefore reaches the client
		// immediately instead of stalling until fully read.
		resp.Body = newFinalizingBody(resp.Body, proxyBodyLimit, finalize)
		return resp
	})

	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", cfg.Port), Handler: proxy}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, err
	}
	runCtx, stopSignals := signal.NotifyContext(ctx, gracefulSignals...)
	defer stopSignals()
	runCtx, cancelTimeout := context.WithTimeout(runCtx, cfg.Timeout)
	defer cancelTimeout()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	showStatus := cfg.StatusWriter != nil && isTerminal(cfg.StatusWriter)
	if showStatus {
		fmt.Fprintf(cfg.StatusWriter, "MITM proxy listening on %s\n", server.Addr)
		status := newStatusLine(cfg.StatusWriter, "Capturing traffic", &flowCount)
		status.start()
		<-runCtx.Done()
		status.stop()
		fmt.Fprintln(cfg.StatusWriter, "MITM proxy stopped")
	} else {
		<-runCtx.Done()
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return nil, err
	}
	if err := <-errCh; err != nil && err != http.ErrServerClosed {
		return nil, err
	}
	// Hijacked MITM connections are not waited on by Shutdown, so a
	// streaming response can still finalize after this point. Close the
	// writers and snapshot the stats under the same lock finalize uses;
	// stragglers then fail cleanly against the closed writer.
	mu.Lock()
	stats.DurationSeconds = time.Since(start).Seconds()
	resultFilteredPath := filtered.Close()
	writerClosed = true
	closeErr := writer.Close()
	statsCopy := stats
	statsCopy.Dropped = make(map[string]int, len(stats.Dropped))
	for key, count := range stats.Dropped {
		statsCopy.Dropped[key] = count
	}
	mu.Unlock()
	if closeErr != nil {
		return nil, closeErr
	}
	if err := WriteSession(bundle, statsCopy); err != nil {
		return nil, err
	}
	return &Result{BundleDir: bundle, FlowsPath: flowsPath, FilteredPath: resultFilteredPath, CAPath: caPath, Stats: statsCopy}, nil
}

func EnsureProxyCA() (string, error) {
	dir, err := proxyConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if certPEM, certErr := os.ReadFile(certPath); certErr == nil {
		if keyPEM, keyErr := os.ReadFile(keyPath); keyErr == nil {
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err == nil {
				cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
				goproxy.GoproxyCa = cert
				return certPath, nil
			}
		}
	}
	certPEM, keyPEM, cert, err := generateProxyCA()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", err
	}
	goproxy.GoproxyCa = cert
	return certPath, nil
}

func generateProxyCA() ([]byte, []byte, tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"apisniff local MITM"},
			CommonName:   "apisniff local MITM CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	cert.Leaf, _ = x509.ParseCertificate(der)
	return certPEM, keyPEM, cert, nil
}

func proxyConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".apisniff"), nil
}

func flowFromProxyRequest(req *http.Request) (model.CapturedFlow, error) {
	rawURL := req.URL.String()
	if !req.URL.IsAbs() {
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		rawURL = scheme + "://" + req.Host + req.URL.RequestURI()
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return model.CapturedFlow{}, err
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	host := strings.ToLower(parsed.Hostname())
	flow := model.NewCapturedFlow(req.Method, rawURL, host, path)
	flow.RequestHeaders = headersToMap(req.Header)
	flow.Tags = appendTag(flow.Tags, "request_proto:"+flowProto(req))
	return flow, nil
}

func flowProto(req *http.Request) string {
	if req == nil {
		return ""
	}
	return req.Proto
}

func headersToMap(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		out[strings.ToLower(key)] = strings.Join(values, "\n")
	}
	return out
}

// captureReader tees a body stream into a size-capped in-memory buffer as the
// real consumer reads it. It never pre-reads and never touches disk, so the
// stream's pacing is untouched.
type captureReader struct {
	rc    io.ReadCloser
	limit int64

	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
	sawEOF    bool
	readErr   error
}

func newCaptureReader(rc io.ReadCloser, limit int64) *captureReader {
	return &captureReader{rc: rc, limit: limit}
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.mu.Lock()
	if n > 0 {
		remaining := c.limit - int64(c.buf.Len())
		switch {
		case remaining >= int64(n):
			c.buf.Write(p[:n])
		case remaining > 0:
			c.buf.Write(p[:remaining])
			c.truncated = true
		default:
			c.truncated = true
		}
	}
	if err == io.EOF {
		c.sawEOF = true
	} else if err != nil && c.readErr == nil {
		c.readErr = err
	}
	c.mu.Unlock()
	return n, err
}

func (c *captureReader) Close() error {
	return c.rc.Close()
}

func (c *captureReader) snapshot() (body []byte, truncated, complete bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...), c.truncated, c.sawEOF, c.readErr
}

// finalizingBody invokes finalize exactly once when the response body
// completes (EOF) or is closed (client done or gone). finalize receives the
// captured prefix, whether it was truncated at the cap, whether the upstream
// stream completed, and any upstream read error.
type finalizingBody struct {
	*captureReader
	once     sync.Once
	finalize func(body []byte, truncated, complete bool, readErr error)
}

func newFinalizingBody(rc io.ReadCloser, limit int64, finalize func(body []byte, truncated, complete bool, readErr error)) *finalizingBody {
	return &finalizingBody{captureReader: newCaptureReader(rc, limit), finalize: finalize}
}

func (f *finalizingBody) Read(p []byte) (int, error) {
	n, err := f.captureReader.Read(p)
	if err != nil {
		f.fire()
	}
	return n, err
}

func (f *finalizingBody) Close() error {
	err := f.captureReader.Close()
	f.fire()
	return err
}

func (f *finalizingBody) fire() {
	f.once.Do(func() {
		f.finalize(f.snapshot())
	})
}

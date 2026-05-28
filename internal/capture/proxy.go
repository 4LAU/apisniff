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
	"syscall"
	"time"

	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/elazarl/goproxy"
)

const proxyBodyLimit = 5 * 1024 * 1024

type proxyRequestState struct {
	flow model.CapturedFlow
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
			writer.Close()
		}
	}()

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
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, pctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		flow, err := flowFromProxyRequest(req)
		if err != nil {
			pctx.UserData = err
			return req, nil
		}
		if req.Body != nil {
			body, replayBody, truncated, readErr := captureBodyForReplay(req.Body, proxyBodyLimit)
			req.Body = replayBody
			if readErr == nil {
				flow.RequestBody = body
				if truncated {
					flow.Tags = appendTag(flow.Tags, "request_body_truncated")
				}
			} else {
				flow.Tags = appendTag(flow.Tags, "request_body_error")
			}
		}
		pctx.UserData = &proxyRequestState{flow: flow}
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
		if resp.Body != nil {
			body, replayBody, truncated, readErr := captureBodyForReplay(resp.Body, proxyBodyLimit)
			resp.Body = replayBody
			if readErr == nil {
				flow.ResponseBody = body
				if truncated {
					flow.Tags = appendTag(flow.Tags, "response_body_truncated")
				}
			} else {
				flow.Tags = appendTag(flow.Tags, "response_body_error")
			}
		}

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
			return resp
		}
		kept.Tags = appendTag(kept.Tags, "category:"+string(classification.Category))
		if err := writer.Write(*kept); err != nil {
			stats.Dropped["write_error"]++
			return resp
		}
		stats.KeptFlows = writer.Count()
		return resp
	})

	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", cfg.Port), Handler: proxy}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, err
	}
	runCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
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
	stats.DurationSeconds = time.Since(start).Seconds()
	if err := writer.Close(); err != nil {
		return nil, err
	}
	writerClosed = true
	if err := WriteSession(bundle, stats); err != nil {
		return nil, err
	}
	return &Result{BundleDir: bundle, FlowsPath: flowsPath, CAPath: caPath, Stats: stats}, nil
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

type removeOnCloseFile struct {
	*os.File
	path string
}

func (f *removeOnCloseFile) Close() error {
	closeErr := f.File.Close()
	removeErr := os.Remove(f.path)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

type limitedCaptureWriter struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (w *limitedCaptureWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len()) < w.limit {
		remaining := int(w.limit - int64(w.buf.Len()))
		if remaining > len(p) {
			remaining = len(p)
		}
		if remaining > 0 {
			_, _ = w.buf.Write(p[:remaining])
		}
		if remaining < len(p) {
			w.truncated = true
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	return len(p), nil
}

func captureBodyForReplay(body io.ReadCloser, limit int64) ([]byte, io.ReadCloser, bool, error) {
	temp, err := os.CreateTemp("", "apisniff-proxy-body-*")
	if err != nil {
		return nil, body, false, err
	}
	defer body.Close()
	capture := &limitedCaptureWriter{limit: limit}
	if _, err := io.Copy(io.MultiWriter(temp, capture), body); err != nil {
		name := temp.Name()
		temp.Close()
		os.Remove(name)
		return nil, io.NopCloser(bytes.NewReader(nil)), false, err
	}
	if _, err := temp.Seek(0, 0); err != nil {
		name := temp.Name()
		temp.Close()
		os.Remove(name)
		return nil, io.NopCloser(bytes.NewReader(nil)), false, err
	}
	return append([]byte(nil), capture.buf.Bytes()...), &removeOnCloseFile{File: temp, path: temp.Name()}, capture.truncated, nil
}

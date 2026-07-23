package capture

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/enetx/g"
	"github.com/enetx/surf"
)

type upstreamHeaderContextKey struct{}

// upstreamTransportOptions controls the transport used for origin requests.
// The legacy path is retained for explicit debugging and rollback only.
type upstreamTransportOptions struct {
	Legacy    bool
	SecureTLS bool
	Timeout   time.Duration
}

// newUpstreamTransport builds the standard client that the capture controller
// can adapt to goproxy's per-request RoundTripper hook.
func newUpstreamTransport(opts upstreamTransportOptions) (*http.Client, func(), error) {
	if opts.Legacy {
		transport := &http.Transport{
			ForceAttemptHTTP2: true,
			Proxy:             http.ProxyFromEnvironment,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: !opts.SecureTLS}, //nolint:gosec
		}
		return &http.Client{Timeout: opts.Timeout, Transport: transport}, transport.CloseIdleConnections, nil
	}

	builder := surf.NewClient().Builder()
	if opts.Timeout > 0 {
		builder = builder.Timeout(opts.Timeout)
	}
	if opts.SecureTLS {
		builder = builder.SecureTLS()
	}
	builder = builder.With(enableTLSResumption, 0)
	builder = builder.With(restoreBrowserHeaders, 1)
	client, err := builder.Impersonate().MacOS().Chrome().Build().Result()
	if err != nil {
		return nil, func() {}, fmt.Errorf("build surf upstream client: %w", err)
	}
	stdClient := client.Std()
	return stdClient, stdClient.CloseIdleConnections, nil
}

type proxyRoundTripper struct {
	transport http.RoundTripper
}

func (rt proxyRoundTripper) RoundTrip(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
	if req.GetBody == nil && (req.Body == nil || req.Body == http.NoBody) {
		req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	}
	req = req.WithContext(context.WithValue(req.Context(), upstreamHeaderContextKey{}, req.Header.Clone()))
	return rt.transport.RoundTrip(req)
}

func enableTLSResumption(client *surf.Client) error {
	client.GetTLSConfig().ClientSessionCache = tls.NewLRUClientSessionCache(0)
	return nil
}

func restoreBrowserHeaders(req *surf.Request) error {
	original, ok := req.GetRequest().Context().Value(upstreamHeaderContextKey{}).(http.Header)
	if !ok {
		return nil
	}
	headers := req.GetRequest().Header
	profileHeaders := headers.Clone()
	for key := range headers {
		delete(headers, key)
	}

	ordered := g.NewMapOrd[string, string]()
	for key, values := range original {
		if !forwardBrowserHeader(key) {
			continue
		}
		if value := headerValue(values); value != "" {
			ordered.Insert(strings.ToLower(key), value)
		}
	}
	for key, values := range profileHeaders {
		if !profileHeaderFallback(key) || ordered.Contains(strings.ToLower(key)) {
			continue
		}
		if value := headerValue(values); value != "" {
			ordered.Insert(strings.ToLower(key), value)
		}
	}
	req.SetHeaders(ordered)
	return nil
}

func forwardBrowserHeader(key string) bool {
	for _, hopByHop := range []string{
		"connection",
		"keep-alive",
		"proxy-connection",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
	} {
		if strings.EqualFold(key, hopByHop) {
			return false
		}
	}
	return true
}

func profileHeaderFallback(key string) bool {
	for _, profileOwned := range []string{
		"user-agent",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
	} {
		if strings.EqualFold(key, profileOwned) {
			return true
		}
	}
	return false
}

func headerValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ", ")
}

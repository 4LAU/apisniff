package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"

	"github.com/4LAU/apisniff-go/internal/model"
)

func DetectGraphQL(ctx context.Context, baseURL string, opts Options) *model.GraphQLResult {
	paths := []string{"/graphql", "/api/graphql", "/gql", "/query"}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec
	}
	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return &model.GraphQLResult{Endpoints: []string{}}
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{Timeout: opts.Timeout, Transport: transport}
	var endpoints []string
	introspection := false
	for _, path := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewBufferString(`{"query":"{__typename}"}`))
		if err != nil {
			continue
		}
		req.Header.Set("content-type", "application/json")
		req.Header.Set("user-agent", chromeUA)
		for key, value := range opts.Headers {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := readLimited(resp.Body, 64*1024)
		resp.Body.Close()
		if resp.StatusCode == 200 && strings.Contains(string(body), "data") {
			endpoints = append(endpoints, path)
			if strings.Contains(string(body), "__typename") {
				introspection = true
			}
		}
	}
	if len(endpoints) == 0 {
		return &model.GraphQLResult{Endpoints: []string{}}
	}
	return &model.GraphQLResult{Endpoints: endpoints, Introspection: introspection}
}

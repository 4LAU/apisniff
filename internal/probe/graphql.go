package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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
	defer transport.CloseIdleConnections()
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
		endpoint := strings.TrimRight(baseURL, "/") + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(`{"query":"{__typename}"}`))
		if err != nil {
			continue
		}
		req.Header.Set("content-type", "application/json")
		req.Header.Set("user-agent", chromeUA)
		if opts.Cookie != "" {
			req.Header.Set("cookie", opts.Cookie)
		}
		for key, value := range opts.Headers {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := readLimited(resp.Body, 64*1024)
		resp.Body.Close()
		if resp.StatusCode == 200 && hasGraphQLDataField(body, "__typename") {
			endpoints = append(endpoints, path)
			if !introspection {
				introspection = checkIntrospection(ctx, client, endpoint, opts)
			}
		}
	}
	if len(endpoints) == 0 {
		return &model.GraphQLResult{Endpoints: []string{}}
	}
	return &model.GraphQLResult{Endpoints: endpoints, Introspection: introspection}
}

func checkIntrospection(ctx context.Context, client *http.Client, endpoint string, opts Options) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(`{"query":"{__schema{queryType{name}}}"}`))
	if err != nil {
		return false
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", chromeUA)
	if opts.Cookie != "" {
		req.Header.Set("cookie", opts.Cookie)
	}
	for key, value := range opts.Headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := readLimited(resp.Body, 64*1024)
	resp.Body.Close()
	return resp.StatusCode == 200 && hasGraphQLDataField(body, "__schema")
}

func hasGraphQLDataField(body []byte, field string) bool {
	var payload struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	value, ok := payload.Data[field]
	return ok && string(value) != "null"
}

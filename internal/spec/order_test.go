package spec

import (
	"math/rand"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

// The generated spec must not depend on flow ingestion order: classification
// learns cross-flow evidence (CSP), schema merging folds conflicting types,
// and auth detection aggregates — all of which could leak input order.
func TestGeneratedSpecIndependentOfFlowOrder(t *testing.T) {
	flows := orderTestFlows()
	want := specYAMLForOrder(t, flows)
	if len(want) == 0 {
		t.Fatal("baseline spec is empty")
	}
	for seed := int64(1); seed <= 5; seed++ {
		shuffled := append([]model.CapturedFlow(nil), flows...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got := specYAMLForOrder(t, shuffled)
		if got != want {
			t.Fatalf("spec differs under shuffle seed %d:\n--- baseline ---\n%s\n--- shuffled ---\n%s", seed, want, got)
		}
	}
}

func specYAMLForOrder(t *testing.T, flows []model.CapturedFlow) string {
	t.Helper()
	pipeline, err := BuildPipeline(flows, "example.com", InclusionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Generate(pipeline.APIFlows, "example.com", pipeline.Auth, Options{InferSchemes: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(doc, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func orderTestFlows() []model.CapturedFlow {
	jsonHeaders := map[string]string{"content-type": "application/json"}
	flow := func(method, host, path string, status int, reqHeaders, respHeaders map[string]string, reqBody, respBody []byte, ts float64) model.CapturedFlow {
		if reqHeaders == nil {
			reqHeaders = map[string]string{}
		}
		return model.CapturedFlow{
			Method:          method,
			Host:            host,
			Path:            path,
			URL:             "https://" + host + path,
			RequestHeaders:  reqHeaders,
			RequestBody:     reqBody,
			ResponseStatus:  status,
			ResponseHeaders: respHeaders,
			ResponseBody:    respBody,
			BodyEncoding:    "base64",
			Tags:            []string{},
			Timestamp:       ts,
		}
	}
	return []model.CapturedFlow{
		// CSP page: marks api-cdn.net as same-site. Order-sensitive without
		// the classifier's two-pass Learn.
		flow("GET", "www.example.com", "/", 200, nil, map[string]string{
			"content-type":            "text/html",
			"content-security-policy": "connect-src 'self' https://api.api-cdn.net",
		}, nil, []byte("<html></html>"), 1),
		// Related-domain API flow: kept only if the CSP evidence is known.
		flow("GET", "api.api-cdn.net", "/v1/data", 200, nil, jsonHeaders, nil, []byte(`{"items":[1,2]}`), 2),
		// Same operation, conflicting schemas: a is integer then string.
		flow("GET", "example.com", "/api/users/1", 200, nil, jsonHeaders, nil, []byte(`{"a":1}`), 3),
		flow("GET", "example.com", "/api/users/2", 200, nil, jsonHeaders, nil, []byte(`{"a":"x","b":true}`), 4),
		// POST with request body schema.
		flow("POST", "example.com", "/api/users", 201, map[string]string{"content-type": "application/json"}, jsonHeaders, []byte(`{"name":"n","age":3}`), []byte(`{"id":9}`), 5),
		// Query parameter evidence across two flows.
		flow("GET", "example.com", "/api/search?q=red&limit=10", 200, nil, jsonHeaders, nil, []byte(`{"hits":[]}`), 6),
		flow("GET", "example.com", "/api/search?q=blue", 200, nil, jsonHeaders, nil, []byte(`{"hits":[]}`), 7),
		// Bearer auth evidence.
		flow("GET", "example.com", "/api/me", 200, map[string]string{"authorization": "Bearer tok"}, jsonHeaders, nil, []byte(`{"me":true}`), 8),
	}
}

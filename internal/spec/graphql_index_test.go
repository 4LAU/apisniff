package spec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func gqlFlow(host, path, op, query, body string) model.CapturedFlow {
	return model.CapturedFlow{Method: "POST", Host: host, Path: path, URL: "https://" + host + path,
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(body), ResponseStatus: 200, ResponseBody: []byte(`{"data":{"ok":1}}`)}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestGraphQLEndpointStripsBothUnions(t *testing.T) {
	flows := []model.CapturedFlow{
		gqlFlow("api.x.com", "/graphql", "A", "query A{a}", `{"operationName":"A","query":"query A{a}","variables":{"x":1}}`),
		gqlFlow("api.x.com", "/graphql", "B", "query B{b}", `{"operationName":"B","query":"query B{b}","variables":{"y":2}}`),
	}
	doc, err := Generate(flows, "api.x.com", nil, Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	post := doc["paths"].(map[string]any)["/graphql"].(map[string]any)["post"].(map[string]any)
	reqSchema := post["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if reqSchema["$ref"] != "#/components/schemas/GraphQLRequestEnvelope" {
		t.Fatalf("request union not stripped: %v", reqSchema)
	}
	respSchema := post["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if respSchema["$ref"] != "#/components/schemas/GraphQLResponseEnvelope" {
		t.Fatalf("response union not stripped: %v", respSchema)
	}
}

func TestGraphQLExtensionIsNormalizedAndSafe(t *testing.T) {
	flows := []model.CapturedFlow{
		gqlFlow("api.x.com", "/properties/123456/graphql", "A", "query A{a}", `{"operationName":"A","query":"query A{a}","variables":{"secret":"TOPSECRET"}}`),
	}
	doc, _ := Generate(flows, "api.x.com", nil, Options{IncludeExamples: true})
	s := mustJSON(doc)
	if strings.Contains(s, "123456") {
		t.Fatalf("raw path id leaked into spec")
	}
	if strings.Contains(s, "TOPSECRET") {
		t.Fatalf("variable value leaked into spec")
	}
	if !strings.Contains(s, "x-apisniff-graphql") {
		t.Fatalf("extension missing")
	}
	if !strings.Contains(s, "/properties/{") {
		t.Fatalf("path should be templated by NormalizeSpecPath")
	}
}

func TestMixedBucketKeepsRESTAndAddsEnvelope(t *testing.T) {
	flows := []model.CapturedFlow{
		{Method: "POST", Host: "api.x.com", Path: "/api", URL: "https://api.x.com/api",
			RequestHeaders: map[string]string{"content-type": "application/json"},
			RequestBody:    []byte(`{"realField":"v"}`), ResponseStatus: 200, ResponseBody: []byte(`{"ok":1}`)},
		gqlFlow("api.x.com", "/api", "A", "query A{a}", `{"operationName":"A","query":"query A{a}"}`),
	}
	doc, _ := Generate(flows, "api.x.com", nil, Options{IncludeExamples: true})
	post := doc["paths"].(map[string]any)["/api"].(map[string]any)["post"].(map[string]any)
	reqSchema := post["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	one, ok := reqSchema["oneOf"].([]any)
	if !ok || len(one) < 2 {
		t.Fatalf("mixed bucket must be oneOf[REST, envelope]: %v", reqSchema)
	}
	ext := post["x-apisniff-graphql"].(map[string]any)
	if ext["mixed"] != true {
		t.Fatalf("mixed flag must be true")
	}
	if !strings.Contains(mustJSON(one), "realField") {
		t.Fatalf("REST schema dropped in mixed bucket")
	}
}

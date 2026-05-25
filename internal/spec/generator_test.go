package spec

import (
	"testing"

	"github.com/4LAU/apisniff-go/internal/auth"
	"github.com/4LAU/apisniff-go/internal/model"
)

func specFlow(method, path string, status int, body []byte) model.CapturedFlow {
	return model.CapturedFlow{
		Method:          method,
		Host:            "example.com",
		Path:            path,
		URL:             "https://example.com" + path,
		RequestHeaders:  map[string]string{},
		RequestBody:     nil,
		ResponseStatus:  status,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    body,
		BodyEncoding:    "base64",
	}
}

func TestInferSchemaObjectAndArray(t *testing.T) {
	schema := InferSchema(map[string]any{"id": float64(1), "name": "Alice", "active": true}, false, "")
	props := asMap(schema["properties"])
	if schema["type"] != "object" || asMap(props["id"])["type"] != "integer" || asMap(props["name"])["type"] != "string" || asMap(props["active"])["type"] != "boolean" {
		t.Fatalf("schema = %#v", schema)
	}
	array := InferSchema([]any{map[string]any{"id": float64(1)}}, false, "")
	if array["type"] != "array" || asMap(array["items"])["type"] != "object" {
		t.Fatalf("array = %#v", array)
	}
}

func TestInferSchemaArrayUsesOneOfForMixedScalarTypes(t *testing.T) {
	schema := InferSchema([]any{float64(1), "two"}, false, "")
	items := asMap(schema["items"])
	oneOf, ok := items["oneOf"].([]any)
	if !ok || len(oneOf) != 2 {
		t.Fatalf("items schema = %#v", items)
	}
	types := map[any]bool{}
	for _, option := range oneOf {
		types[asMap(option)["type"]] = true
	}
	if !types["integer"] || !types["string"] {
		t.Fatalf("oneOf = %#v", oneOf)
	}
}

func TestGenerateOpenAPIBasicAndNormalize(t *testing.T) {
	doc := Generate([]model.CapturedFlow{
		specFlow("GET", "/api/v1/users", 200, []byte(`[{"id":1,"name":"Alice"}]`)),
		specFlow("GET", "/api/v1/users/123", 200, []byte(`{"id":123,"name":"Bob"}`)),
		specFlow("POST", "/api/v1/users", 200, []byte(`{"id":124}`)),
	}, "example.com", nil, Options{})
	paths := asMap(doc["paths"])
	if doc["openapi"] != "3.0.3" || paths["/api/v1/users"] == nil || paths["/api/v1/users/{id}"] == nil {
		t.Fatalf("doc = %#v", doc)
	}
}

func TestQueryParamsAndResponseSchemaMerging(t *testing.T) {
	doc := Generate([]model.CapturedFlow{
		specFlow("GET", "/api/v1/users?page=1", 200, []byte(`{"id":1}`)),
		specFlow("GET", "/api/v1/users?page=2&sort=name", 200, []byte(`{"id":2,"email":"a@b.com"}`)),
		specFlow("GET", "/api/v1/users", 404, []byte(`{"error":"not found"}`)),
	}, "example.com", nil, Options{})
	get := operation(doc, "/api/v1/users", "get")
	params := get["parameters"].([]any)
	if len(params) != 2 {
		t.Fatalf("params = %#v", params)
	}
	responses := asMap(get["responses"])
	if responses["200"] == nil || responses["404"] == nil {
		t.Fatalf("responses = %#v", responses)
	}
	schema := responseSchema(doc, "/api/v1/users", "get", "200")
	props := asMap(schema["properties"])
	if props["id"] == nil || props["email"] == nil {
		t.Fatalf("props = %#v", props)
	}
}

func TestRequestBodies(t *testing.T) {
	jsonPost := specFlow("POST", "/api/v1/users", 200, []byte(`{"ok":true}`))
	jsonPost.RequestHeaders = map[string]string{"content-type": "application/json"}
	jsonPost.RequestBody = []byte(`{"name":"Alice"}`)

	formPost := specFlow("POST", "/api/v1/login", 200, []byte(`{"ok":true}`))
	formPost.RequestHeaders = map[string]string{"content-type": "application/x-www-form-urlencoded"}
	formPost.RequestBody = []byte("username=alice&password=secret")

	mp := specFlow("POST", "/api/v1/upload", 200, []byte(`{"ok":true}`))
	mp.RequestHeaders = map[string]string{"content-type": "multipart/form-data; boundary=bound"}
	mp.RequestBody = []byte("--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.jpg\"\r\n\r\nx\r\n--bound--")

	doc := Generate([]model.CapturedFlow{jsonPost, formPost, mp}, "example.com", nil, Options{})
	if requestSchema(doc, "/api/v1/users", "post", "application/json")["type"] != "object" {
		t.Fatalf("json request missing")
	}
	if requestSchema(doc, "/api/v1/login", "post", "application/x-www-form-urlencoded")["type"] != "object" {
		t.Fatalf("form request missing")
	}
	file := asMap(asMap(requestSchema(doc, "/api/v1/upload", "post", "multipart/form-data")["properties"])["file"])
	if file["format"] != "binary" {
		t.Fatalf("file schema = %#v", file)
	}
}

func TestParseMultipartQuotedBoundary(t *testing.T) {
	body := []byte("--bound\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nalice\r\n--bound--")
	parsed := ParseMultipart(body, `multipart/form-data; boundary="bound"`)
	if parsed["username"] != "alice" {
		t.Fatalf("multipart fields = %#v", parsed)
	}
}

func TestExamplesRedactSecrets(t *testing.T) {
	doc := Generate([]model.CapturedFlow{
		specFlow("GET", "/api/v1/users", 200, []byte(`{"password":"hunter2","author":"Jane","token":"bearer abc"}`)),
	}, "example.com", nil, Options{IncludeExamples: true})
	props := asMap(responseSchema(doc, "/api/v1/users", "get", "200")["properties"])
	if asMap(props["password"])["example"] != "***REDACTED***" || asMap(props["token"])["example"] != "***REDACTED***" || asMap(props["author"])["example"] != "Jane" {
		t.Fatalf("props = %#v", props)
	}
}

func TestObservedAuthAndSecuritySchemes(t *testing.T) {
	doc := Generate([]model.CapturedFlow{specFlow("GET", "/api/v1/users", 200, []byte(`{"ok":true}`))}, "example.com", []auth.Pattern{
		{AuthType: "bearer", Detail: "authorization: bearer", FlowCount: 5},
		{AuthType: "token_endpoint", Detail: "/oauth/token", FlowCount: 1},
	}, Options{InferSchemes: true})
	if doc["x-observed-auth"] == nil || doc["x-observed-token-endpoints"] == nil {
		t.Fatalf("auth extensions missing: %#v", doc)
	}
	schemes := asMap(asMap(doc["components"])["securitySchemes"])
	if asMap(schemes["bearer"])["scheme"] != "bearer" {
		t.Fatalf("schemes = %#v", schemes)
	}
	if doc["security"] != nil {
		t.Fatalf("unexpected top-level security")
	}
}

func operation(doc map[string]any, path, method string) map[string]any {
	return asMap(asMap(asMap(doc["paths"])[path])[method])
}

func responseSchema(doc map[string]any, path, method, status string) map[string]any {
	return asMap(asMap(asMap(asMap(asMap(operation(doc, path, method)["responses"])[status])["content"])["application/json"])["schema"])
}

func requestSchema(doc map[string]any, path, method, contentType string) map[string]any {
	return asMap(asMap(asMap(asMap(operation(doc, path, method)["requestBody"])["content"])[contentType])["schema"])
}

package spec

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/jsonschema"
	"github.com/4LAU/apisniff/internal/model"
)

func mustGenerate(t testing.TB, flows []model.CapturedFlow, domain string, patterns []auth.Pattern, opts Options) map[string]any {
	t.Helper()
	doc, err := Generate(flows, domain, patterns, opts)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

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

type flowOption func(*model.CapturedFlow)

func testFlow(opts ...flowOption) model.CapturedFlow {
	flow := specFlow("GET", "/api/v1/users", 200, []byte(`[{"id":1,"name":"Alice"}]`))
	for _, opt := range opts {
		opt(&flow)
	}
	return flow
}

func withMethod(method string) flowOption {
	return func(flow *model.CapturedFlow) {
		flow.Method = method
	}
}

func withPath(path string) flowOption {
	return func(flow *model.CapturedFlow) {
		flow.Path = path
		flow.URL = "https://" + flow.Host + path
	}
}

func withRequest(contentType string, body []byte) flowOption {
	return func(flow *model.CapturedFlow) {
		flow.RequestHeaders = map[string]string{"content-type": contentType}
		flow.RequestBody = body
	}
}

func withResponse(status int, contentType string, body []byte) flowOption {
	return func(flow *model.CapturedFlow) {
		flow.ResponseStatus = status
		flow.ResponseHeaders = map[string]string{"content-type": contentType}
		flow.ResponseBody = body
	}
}

func withTags(tags ...string) flowOption {
	return func(flow *model.CapturedFlow) {
		flow.Tags = tags
	}
}

func TestGenerateReturnsErrNoValidAPIFlows(t *testing.T) {
	_, err := Generate([]model.CapturedFlow{
		specFlow("CONNECT", "/api/tunnel", 200, []byte(`{"ignored":true}`)),
		specFlow("GET", "", 200, []byte(`{"ignored":true}`)),
		specFlow("GET", "/api/status/zero", 0, []byte(`{"ignored":true}`)),
		specFlow("GET", "/users/{broken", 200, []byte(`{"ignored":true}`)),
	}, "example.com", nil, Options{})
	if !errors.Is(err, ErrNoValidAPIFlows) {
		t.Fatalf("err = %v, want ErrNoValidAPIFlows", err)
	}
}

func FuzzGenerator(f *testing.F) {
	f.Add(uint8(0), "api/v1/users/123", uint16(200), []byte(`{"name":"Ada"}`), []byte(`{"ok":true}`), uint8(0))
	f.Add(uint8(1), "/api/orders/{orderId}", uint16(201), []byte(`[1,2,3]`), []byte(`null`), uint8(1))
	f.Add(uint8(6), "search?q=test", uint16(499), []byte(`"request"`), []byte(`{"error":{"code":"x"}}`), uint8(0))

	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"}
	contentTypes := []string{"application/json", "application/problem+json", "application/vnd.apisniff+json"}

	f.Fuzz(func(t *testing.T, methodSeed uint8, rawPath string, statusSeed uint16, requestSeed []byte, responseSeed []byte, contentTypeSeed uint8) {
		method := methods[int(methodSeed)%len(methods)]
		status := 100 + int(statusSeed%500)
		path := fuzzSpecPath(rawPath)
		contentType := contentTypes[int(contentTypeSeed)%len(contentTypes)]

		flow := specFlow(method, path, status, fuzzJSONBody(responseSeed))
		flow.ResponseHeaders = map[string]string{"content-type": contentType}
		if method == "POST" || method == "PUT" || method == "PATCH" {
			flow.RequestHeaders = map[string]string{"content-type": "application/json"}
			flow.RequestBody = fuzzJSONBody(requestSeed)
		}

		doc, err := Generate([]model.CapturedFlow{flow}, "example.com", nil, Options{IncludeExamples: true})
		if err != nil {
			t.Fatalf("Generate returned error for constrained flow: %v", err)
		}
		if _, err := MarshalAndValidate(doc, "json"); err != nil {
			t.Fatalf("generated spec did not validate: %v", err)
		}
	})
}

func fuzzSpecPath(raw string) string {
	if raw == "" {
		return "/api/fuzz"
	}
	parts := strings.Split(strings.SplitN(raw, "?", 2)[0], "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			clean = append(clean, "{itemId}")
			continue
		}
		segment := make([]byte, 0, len(part))
		for i := 0; i < len(part) && len(segment) < 24; i++ {
			c := part[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
				segment = append(segment, c)
			}
		}
		if len(segment) > 0 {
			clean = append(clean, string(segment))
		}
		if len(clean) == 8 {
			break
		}
	}
	if len(clean) == 0 {
		return "/api/fuzz"
	}
	return "/" + strings.Join(clean, "/")
}

func fuzzJSONBody(seed []byte) []byte {
	var value any
	switch {
	case len(seed) == 0:
		value = nil
	case seed[0]%5 == 0:
		value = string(seed[1:])
	case seed[0]%5 == 1:
		value = int(seed[0]) + len(seed)
	case seed[0]%5 == 2:
		value = seed[0]%2 == 0
	case seed[0]%5 == 3:
		items := make([]any, 0, min(len(seed), 8))
		for _, b := range seed[:min(len(seed), 8)] {
			items = append(items, int(b))
		}
		value = items
	default:
		value = map[string]any{
			"value": string(seed[1:]),
			"size":  len(seed),
			"nested": map[string]any{
				"first": int(seed[0]),
				"last":  int(seed[len(seed)-1]),
			},
		}
	}
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func TestInferSchemaObjectAndArray(t *testing.T) {
	schema := jsonschema.InferSchema(map[string]any{"id": float64(1), "name": "Alice", "active": true}, false, "")
	props := asMap(schema["properties"])
	if schema["type"] != "object" || asMap(props["id"])["type"] != "integer" || asMap(props["name"])["type"] != "string" || asMap(props["active"])["type"] != "boolean" {
		t.Fatalf("schema = %#v", schema)
	}
	array := jsonschema.InferSchema([]any{map[string]any{"id": float64(1)}}, false, "")
	if array["type"] != "array" || asMap(array["items"])["type"] != "object" {
		t.Fatalf("array = %#v", array)
	}
}

func TestInferSchemaNullIsNullableString(t *testing.T) {
	schema := jsonschema.InferSchema(nil, false, "")
	if schema["type"] != "string" || schema["nullable"] != true {
		t.Fatalf("schema = %#v", schema)
	}
}

func TestInferSchemaEmptyArrayHasOpenItems(t *testing.T) {
	schema := jsonschema.InferSchema([]any{}, false, "")
	if schema["type"] != "array" || len(asMap(schema["items"])) != 0 {
		t.Fatalf("schema = %#v", schema)
	}
}

func TestInferSchemaNestedArraysMergeItemSchemas(t *testing.T) {
	schema := jsonschema.InferSchema([]any{
		[]any{map[string]any{"id": float64(1)}},
		[]any{map[string]any{"name": "Alice"}},
	}, false, "")
	outerItems := asMap(schema["items"])
	innerItems := asMap(outerItems["items"])
	props := asMap(innerItems["properties"])
	if schema["type"] != "array" || outerItems["type"] != "array" || props["id"] == nil || props["name"] == nil {
		t.Fatalf("schema = %#v", schema)
	}
}

func TestInferSchemaNumericKeyedObjectAsMap(t *testing.T) {
	schema := jsonschema.InferSchema(map[string]any{
		"123": map[string]any{"name": "Alice"},
		"456": map[string]any{"name": "Bob"},
	}, false, "")
	if schema["type"] != "object" || schema["properties"] != nil {
		t.Fatalf("schema = %#v", schema)
	}
	props := asMap(asMap(schema["additionalProperties"])["properties"])
	if asMap(props["name"])["type"] != "string" {
		t.Fatalf("additionalProperties = %#v", schema["additionalProperties"])
	}
}

func TestInferSchemaEmptyNumericKeyedObjectFallsBackToObjectProperties(t *testing.T) {
	schema := jsonschema.InferSchema(map[string]any{}, false, "")
	if schema["type"] != "object" || schema["properties"] == nil || schema["additionalProperties"] != nil {
		t.Fatalf("schema = %#v", schema)
	}
}

func TestInferSchemaNullableArrayItems(t *testing.T) {
	schema := jsonschema.InferSchema([]any{nil, "Alice"}, false, "")
	items := asMap(schema["items"])
	if items["type"] != "string" || items["nullable"] != true {
		t.Fatalf("items = %#v", items)
	}
}

func TestInferSchemaArrayFallsBackToStringForMixedScalarTypes(t *testing.T) {
	schema := jsonschema.InferSchema([]any{float64(1), "two"}, false, "")
	items := asMap(schema["items"])
	if items["type"] != "string" {
		t.Fatalf("items schema = %#v", items)
	}
	observed, ok := items["x-apisniff-observed-types"].([]any)
	if !ok || len(observed) != 2 || observed[0] != "integer" || observed[1] != "string" {
		t.Fatalf("observed types = %#v", observed)
	}
}

func TestMergeSchemasConflictingScalarTypesFallBackToString(t *testing.T) {
	merged := jsonschema.MergeSchemas(map[string]any{"type": "integer"}, map[string]any{"type": "string"})
	observed := toAnySlice(merged["x-apisniff-observed-types"])
	if merged["type"] != "string" || len(observed) != 2 || observed[0] != "integer" || observed[1] != "string" {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestMergeSchemasPromotesNullableSameType(t *testing.T) {
	merged := jsonschema.MergeSchemas(map[string]any{"type": "string"}, map[string]any{"type": "string", "nullable": true})
	if merged["type"] != "string" || merged["nullable"] != true {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestMergeSchemasMergesObjectProperties(t *testing.T) {
	merged := jsonschema.MergeSchemas(
		map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}},
		map[string]any{"type": "object", "properties": map[string]any{"email": map[string]any{"type": "string"}}},
	)
	props := asMap(merged["properties"])
	if asMap(props["id"])["type"] != "integer" || asMap(props["email"])["type"] != "string" {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestMergeSchemasEnrichesEmptyArrayItems(t *testing.T) {
	merged := jsonschema.MergeSchemas(
		map[string]any{"type": "array", "items": map[string]any{}},
		map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}}},
	)
	items := asMap(merged["items"])
	if items["type"] != "object" || asMap(asMap(items["properties"])["id"])["type"] != "integer" {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestMergeSchemasKeepsStructuredTypeOverScalar(t *testing.T) {
	merged := jsonschema.MergeSchemas(
		map[string]any{"type": "string", "nullable": true},
		map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}},
	)
	if merged["type"] != "object" || merged["nullable"] != true || asMap(merged["properties"])["id"] == nil {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestMergeSchemasAdditionalPropertiesWinsOverProperties(t *testing.T) {
	merged := jsonschema.MergeSchemas(
		map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}},
		map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
	)
	if merged["properties"] != nil || asMap(merged["additionalProperties"])["type"] != "string" {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestGenerateOpenAPIBasicAndNormalize(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		specFlow("GET", "/api/v1/users", 200, []byte(`[{"id":1,"name":"Alice"}]`)),
		specFlow("GET", "/api/v1/users/123", 200, []byte(`{"id":123,"name":"Bob"}`)),
		specFlow("POST", "/api/v1/users", 200, []byte(`{"id":124}`)),
	}, "example.com", nil, Options{})
	paths := asMap(doc["paths"])
	if doc["openapi"] != "3.0.3" || paths["/api/v1/users"] == nil || paths["/api/v1/users/{userId}"] == nil {
		t.Fatalf("doc = %#v", doc)
	}
}

func TestQueryParamsAndResponseSchemaMerging(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
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

	doc := mustGenerate(t, []model.CapturedFlow{jsonPost, formPost, mp}, "example.com", nil, Options{})
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

func TestJSONRequestBodySchemasMergeAcrossFlows(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withMethod("POST"), withRequest("application/json", []byte(`{"name":"Alice"}`))),
		testFlow(withMethod("POST"), withRequest("application/json", []byte(`{"name":"Bob","age":30}`))),
	}, "example.com", nil, Options{})
	props := asMap(requestSchema(doc, "/api/v1/users", "post", "application/json")["properties"])
	if asMap(props["name"])["type"] != "string" || asMap(props["age"])["type"] != "integer" {
		t.Fatalf("props = %#v", props)
	}
}

func TestFormURLEncodedRequestBodySchema(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withMethod("POST"), withRequest("application/x-www-form-urlencoded", []byte("username=alice&password=secret"))),
	}, "example.com", nil, Options{})
	props := asMap(requestSchema(doc, "/api/v1/users", "post", "application/x-www-form-urlencoded")["properties"])
	if asMap(props["username"])["type"] != "string" || asMap(props["password"])["type"] != "string" {
		t.Fatalf("props = %#v", props)
	}
}

func TestMultipartRequestBodyIncludesTextAndBinaryFields(t *testing.T) {
	body := []byte("--bound\r\n" +
		"Content-Disposition: form-data; name=\"description\"\r\n\r\n" +
		"A file upload\r\n" +
		"--bound\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n" +
		"Content-Type: image/jpeg\r\n\r\n" +
		"<binary data>\r\n" +
		"--bound--")
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withMethod("POST"), withPath("/api/v1/upload"), withRequest("multipart/form-data; boundary=bound", body)),
	}, "example.com", nil, Options{})
	props := asMap(requestSchema(doc, "/api/v1/upload", "post", "multipart/form-data")["properties"])
	if asMap(props["description"])["type"] != "string" || asMap(props["file"])["format"] != "binary" {
		t.Fatalf("props = %#v", props)
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
	doc := mustGenerate(t, []model.CapturedFlow{
		specFlow("GET", "/api/v1/users", 200, []byte(`{"password":"hunter2","author":"Jane","token":"bearer abc"}`)),
	}, "example.com", nil, Options{IncludeExamples: true})
	props := asMap(responseSchema(doc, "/api/v1/users", "get", "200")["properties"])
	if asMap(props["password"])["example"] != "***REDACTED***" || asMap(props["token"])["example"] != "***REDACTED***" || asMap(props["author"])["example"] != "Jane" {
		t.Fatalf("props = %#v", props)
	}
}

func TestExamplesRedactNestedSensitiveField(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withResponse(200, "application/json", []byte(`{"user":{"name":"alice","credential":"s3cr3t"}}`))),
	}, "example.com", nil, Options{IncludeExamples: true})
	nested := asMap(asMap(asMap(responseSchema(doc, "/api/v1/users", "get", "200")["properties"])["user"])["properties"])
	if asMap(nested["name"])["example"] != "alice" || asMap(nested["credential"])["example"] != "***REDACTED***" {
		t.Fatalf("nested props = %#v", nested)
	}
}

func TestExamplesSensitiveFieldBoundaries(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withResponse(200, "application/json", []byte(`{"auth":"x","author":"Jane","secret":"s","secretariat":"UN","token":"t","max_tokens":100}`))),
	}, "example.com", nil, Options{IncludeExamples: true})
	props := asMap(responseSchema(doc, "/api/v1/users", "get", "200")["properties"])
	if asMap(props["auth"])["example"] != "***REDACTED***" ||
		asMap(props["author"])["example"] != "Jane" ||
		asMap(props["secret"])["example"] != "***REDACTED***" ||
		asMap(props["secretariat"])["example"] != "UN" ||
		asMap(props["token"])["example"] != "***REDACTED***" ||
		asMap(props["max_tokens"])["example"] != int64(100) {
		t.Fatalf("props = %#v", props)
	}
}

func TestMultipartSensitiveFieldExampleRedacted(t *testing.T) {
	body := []byte("--bound\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--bound--")
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withMethod("POST"), withPath("/api/v1/login"), withRequest("multipart/form-data; boundary=bound", body)),
	}, "example.com", nil, Options{IncludeExamples: true})
	props := asMap(requestSchema(doc, "/api/v1/login", "post", "multipart/form-data")["properties"])
	if asMap(props["password"])["example"] != "***REDACTED***" {
		t.Fatalf("props = %#v", props)
	}
}

func TestObservedAuthAndSecuritySchemes(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{specFlow("GET", "/api/v1/users", 200, []byte(`{"ok":true}`))}, "example.com", []auth.Pattern{
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

func TestObservedAuthDefaultDoesNotInferSecuritySchemes(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{testFlow()}, "example.com", []auth.Pattern{
		{AuthType: "bearer", Detail: "authorization: bearer", FlowCount: 5},
	}, Options{})
	if doc["x-observed-auth"] == nil {
		t.Fatalf("auth extensions missing: %#v", doc)
	}
	if asMap(asMap(doc["components"])["securitySchemes"]) != nil && len(asMap(asMap(doc["components"])["securitySchemes"])) > 0 {
		t.Fatalf("unexpected securitySchemes: %#v", asMap(doc["components"]))
	}
}

func TestSecuritySchemesInferAPIKeyAndCookie(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{testFlow()}, "example.com", []auth.Pattern{
		{AuthType: "api_key_header", Detail: "x-api-key", FlowCount: 2},
		{AuthType: "api_key_query", Detail: "api_key", FlowCount: 1},
		{AuthType: "session_cookie", Detail: "sessionid", FlowCount: 3},
	}, Options{InferSchemes: true})
	schemes := asMap(asMap(doc["components"])["securitySchemes"])
	header := asMap(schemes["api_key_header"])
	query := asMap(schemes["api_key_query"])
	cookie := asMap(schemes["session_cookie"])
	if header["type"] != "apiKey" || header["in"] != "header" || header["name"] != "x-api-key" ||
		query["type"] != "apiKey" || query["in"] != "query" || query["name"] != "api_key" ||
		cookie["type"] != "apiKey" || cookie["in"] != "cookie" || cookie["name"] != "sessionid" {
		t.Fatalf("schemes = %#v", schemes)
	}
}

func TestSecuritySchemesInferMultipleHTTPTypes(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{testFlow()}, "example.com", []auth.Pattern{
		{AuthType: "bearer", Detail: "authorization: bearer", FlowCount: 5},
		{AuthType: "basic", Detail: "authorization: basic", FlowCount: 1},
	}, Options{InferSchemes: true})
	schemes := asMap(asMap(doc["components"])["securitySchemes"])
	if asMap(schemes["bearer"])["scheme"] != "bearer" || asMap(schemes["basic"])["scheme"] != "basic" {
		t.Fatalf("schemes = %#v", schemes)
	}
	if doc["security"] != nil {
		t.Fatalf("unexpected top-level security: %#v", doc["security"])
	}
}

func TestSecuritySchemeComponentsPreservedDuringSchemaPromotion(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withPath("/api/v1/users/1"), withResponse(200, "application/json", []byte(`{"id":1,"name":"Alice"}`))),
		testFlow(withPath("/api/v1/customers/2"), withResponse(200, "application/json", []byte(`{"id":2,"name":"Bob"}`))),
	}, "example.com", []auth.Pattern{
		{AuthType: "bearer", Detail: "authorization: bearer", FlowCount: 2},
	}, Options{InferSchemes: true})
	components := asMap(doc["components"])
	if asMap(components["securitySchemes"])["bearer"] == nil || asMap(components["schemas"]) == nil {
		t.Fatalf("components = %#v", components)
	}
	if asMap(responseMedia(doc, "/api/v1/users/{userId}", "get", "200", "application/json")["schema"])["$ref"] == nil {
		t.Fatalf("response schema was not promoted: %#v", responseMedia(doc, "/api/v1/users/{userId}", "get", "200", "application/json"))
	}
}

func TestIsAPIFlowFormPostWithHTMLResponse(t *testing.T) {
	flow := testFlow(
		withMethod("POST"),
		withRequest("application/x-www-form-urlencoded", []byte("username=alice&password=secret")),
		withResponse(200, "text/html", []byte("<html>OK</html>")),
	)
	if !IsAPIFlow(flow) {
		t.Fatal("expected form POST to be API flow")
	}
}

func TestIsAPIFlowPureHTMLGetExcluded(t *testing.T) {
	flow := testFlow(withPath("/"), withResponse(200, "text/html", []byte("<html><body>Hello</body></html>")))
	if IsAPIFlow(flow) {
		t.Fatal("expected pure HTML GET to be excluded")
	}
}

func TestFilterAPIFlowsIncludesTaggedBusinessAuthAndAntibot(t *testing.T) {
	flows := []model.CapturedFlow{
		testFlow(withPath("/"), withResponse(200, "text/html", []byte("<html>business</html>")), withTags("category:business_api")),
		testFlow(withPath("/oauth/token"), withResponse(200, "text/html", []byte("<html>auth</html>")), withTags("category:auth")),
		testFlow(withPath("/sensor"), withResponse(200, "text/html", []byte("<html>antibot</html>")), withTags("category:antibot")),
		testFlow(withPath("/page"), withResponse(200, "text/html", []byte("<html>page</html>"))),
	}
	filtered := FilterAPIFlows(flows)
	if len(filtered) != 3 {
		t.Fatalf("len(filtered) = %d, want 3", len(filtered))
	}
	paths := map[string]bool{}
	for _, f := range filtered {
		paths[f.Path] = true
	}
	if !paths["/"] || !paths["/oauth/token"] || !paths["/sensor"] {
		t.Fatalf("wrong flows survived: %v", paths)
	}
}

func TestQueryParamObservationMetadataDoesNotLeakValues(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		testFlow(withPath("/api/v1/users?token=secret-one&page=1")),
		testFlow(withPath("/api/v1/users?token=secret-two&sort=name")),
	}, "example.com", nil, Options{})
	params := map[string]map[string]any{}
	for _, paramValue := range toAnySlice(operation(doc, "/api/v1/users", "get")["parameters"]) {
		param := asMap(paramValue)
		if param["in"] == "query" {
			params[param["name"].(string)] = param
		}
	}
	if len(params) != 3 || params["token"] == nil || params["page"] == nil || params["sort"] == nil {
		t.Fatalf("params = %#v", params)
	}
	observed := asMap(params["token"]["x-apisniff-observed"])
	if observed["present_count"] != 2 || observed["total_count"] != 2 || observed["distinct_value_count"] != 2 || observed["inferred_type"] != "string" {
		t.Fatalf("observed = %#v", observed)
	}
	data, err := Marshal(doc, "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-one") || strings.Contains(string(data), "secret-two") {
		t.Fatalf("query value leaked into spec: %s", data)
	}
}

func operation(doc map[string]any, path, method string) map[string]any {
	return asMap(asMap(asMap(doc["paths"])[path])[method])
}

func responseSchema(doc map[string]any, path, method, status string) map[string]any {
	return resolveSchema(doc, asMap(responseMedia(doc, path, method, status, "application/json")["schema"]))
}

func responseMedia(doc map[string]any, path, method, status, contentType string) map[string]any {
	return asMap(asMap(asMap(asMap(operation(doc, path, method)["responses"])[status])["content"])[contentType])
}

func requestSchema(doc map[string]any, path, method, contentType string) map[string]any {
	return resolveSchema(doc, asMap(asMap(asMap(asMap(operation(doc, path, method)["requestBody"])["content"])[contentType])["schema"]))
}

func resolveSchema(doc map[string]any, schema map[string]any) map[string]any {
	ref, _ := schema["$ref"].(string)
	if ref == "" {
		return schema
	}
	const prefix = "#/components/schemas/"
	if !strings.HasPrefix(ref, prefix) {
		return schema
	}
	return asMap(asMap(asMap(doc["components"])["schemas"])[strings.TrimPrefix(ref, prefix)])
}

func TestGenerateOpaqueIDsCollapse(t *testing.T) {
	doc := mustGenerate(t, []model.CapturedFlow{
		// prefixed ids: two prefixes plus a one-char prefix and a nested id
		specFlow("GET", "/creditcards/cc_9BMqukMwYVs6SY1psJlh0f", 200, []byte(`{"id":"cc_9BMqukMwYVs6SY1psJlh0f"}`)),
		specFlow("GET", "/creditcards/cc_7w7CLKmd9I77HX2fjHfGPB", 200, []byte(`{"id":"cc_7w7CLKmd9I77HX2fjHfGPB"}`)),
		specFlow("GET", "/creditcards/cc_5KnE6YhtaoBAKMydT1kPir", 200, []byte(`{"id":"cc_5KnE6YhtaoBAKMydT1kPir"}`)),
		specFlow("GET", "/users/u_3fsKhZHvqRFAo7XXNOz4Lv", 200, []byte(`{"id":"u_3fsKhZHvqRFAo7XXNOz4Lv"}`)),
		specFlow("GET", "/users/u_8KpQ2mNvBcXr5TdWfHj1Ay", 200, []byte(`{"id":"u_8KpQ2mNvBcXr5TdWfHj1Ay"}`)),
		// nested prefixed id followed by a static sub-route
		specFlow("GET", "/organizations/org_AYPx4TzpatN9Bm3xW9VQUf/departments", 200, []byte(`[]`)),
		specFlow("GET", "/organizations/org_BBz9KmLpQrSt7uVwXy2Zab/departments", 200, []byte(`[]`)),
		// bare ULIDs (no prefix)
		specFlow("GET", "/events/01ARZ3NDEKTSV4RRFFQ69G5FAV", 200, []byte(`{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}`)),
		specFlow("GET", "/events/01BX5ZZKBKACTAV9WEVGEMMVRZ", 200, []byte(`{"id":"01BX5ZZKBKACTAV9WEVGEMMVRZ"}`)),
		// static route family under the same parent must NOT collapse
		specFlow("GET", "/users/search", 200, []byte(`[]`)),
		specFlow("GET", "/users/notifications", 200, []byte(`[]`)),
	}, "example.com", nil, Options{})

	paths := asMap(doc["paths"])
	want := []string{
		"/creditcards/{creditcardId}",
		"/users/{userId}",
		"/organizations/{organizationId}/departments",
		"/events/{eventId}",
		"/users/search",
		"/users/notifications",
	}
	for _, p := range want {
		if paths[p] == nil {
			t.Errorf("expected path %q in spec, missing", p)
		}
	}
	// Leak guard runs before the count assertion so it stays load-bearing: a raw
	// id surviving would also change the count, and a fatal count check here would
	// shadow this loop. Templated param names are camelCase (creditcardId, userId),
	// so any "_" in a path means a raw prefixed id (cc_/u_/org_) leaked through.
	for p := range paths {
		if strings.ContainsAny(p, "_") || strings.Contains(p, "01ARZ3") || strings.Contains(p, "01BX5Z") {
			t.Errorf("raw id leaked into path %q", p)
		}
	}
	if len(paths) != len(want) {
		t.Fatalf("path count = %d, want %d: %#v", len(paths), len(want), paths)
	}
}

func TestNonJSONResponseDocumentedAsSchemalessMediaType(t *testing.T) {
	flow := specFlow("GET", "/bin/rewards-catalog/list", 200, []byte("<li class=tile></li>"))
	flow.ResponseHeaders = map[string]string{"content-type": "text/html; charset=utf-8"}
	doc := mustGenerate(t, []model.CapturedFlow{flow}, "example.com", nil, Options{})

	paths := asMap(doc["paths"])
	op := asMap(asMap(paths["/bin/rewards-catalog/list"])["get"])
	responses := asMap(op["responses"])
	resp200 := asMap(responses["200"])
	content := asMap(resp200["content"])
	media, ok := content["text/html"]
	if !ok {
		t.Fatalf("text/html media type missing; content = %#v", content)
	}
	mediaMap := asMap(media)
	if _, hasSchema := mediaMap["schema"]; hasSchema {
		t.Fatalf("text/html media type must have no schema, got %#v", mediaMap)
	}
}

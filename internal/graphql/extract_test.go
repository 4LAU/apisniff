package graphql

import (
	"bytes"
	"mime/multipart"
	"net/url"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

// buildMultipart returns a multipart/form-data body with an "operations" field
// set to ops, plus the matching content-type header value.
func buildMultipart(t *testing.T, ops string) (body []byte, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("operations", ops); err != nil {
		t.Fatalf("write field: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

func TestExtractJSONObjectQuery(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"GetUser","query":"query GetUser($id:ID!){user(id:$id){name}}","variables":{"id":"7"}}`),
		ResponseStatus: 200,
		ResponseBody:   []byte(`{"data":{"user":{"name":"L"}}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 {
		t.Fatalf("want 1 op, got %d", len(ops))
	}
	op := ops[0]
	if op.OperationName != "GetUser" || op.OperationType != "query" {
		t.Fatalf("name/type: %q/%q", op.OperationName, op.OperationType)
	}
	if op.Transport != "json" {
		t.Fatalf("transport %q", op.Transport)
	}
	if op.PersistedHash != "" {
		t.Fatalf("unexpected hash")
	}
	if string(op.ResponseBody) == "" {
		t.Fatalf("missing response")
	}
}

func TestExtractPersistedHashOnly(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "vrbo.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"PayoutSummaryTable","variables":{"x":1},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 {
		t.Fatalf("want 1, got %d", len(ops))
	}
	if ops[0].PersistedHash != "abc123" {
		t.Fatalf("hash %q", ops[0].PersistedHash)
	}
	if ops[0].Query != "" {
		t.Fatalf("expected no query")
	}
	if ops[0].OperationType != "unknown" {
		t.Fatalf("type %q (must not fabricate)", ops[0].OperationType)
	}
}

func TestExtractBatchIndexMatched(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`[{"operationName":"A","query":"query A{a}"},{"operationName":"B","query":"query B{b}"}]`),
		ResponseStatus: 200,
		ResponseBody:   []byte(`[{"data":{"a":1}},{"data":{"b":2}}]`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 2 {
		t.Fatalf("want 2, got %d", len(ops))
	}
	if ops[0].Transport != "json-batch" {
		t.Fatalf("transport")
	}
	if string(ops[1].ResponseBody) != `{"data":{"b":2}}` {
		t.Fatalf("index-match wrong: %s", ops[1].ResponseBody)
	}
}

func TestExtractBatchSkipsNonGraphQLElements(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`[{"name":"L","email":"l@example.com"},{"operationName":"B","query":"query B{b}"}]`),
		ResponseStatus: 200,
		ResponseBody:   []byte(`[{"id":1},{"data":{"b":2}}]`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 {
		t.Fatalf("want 1 op (non-GraphQL element skipped), got %d", len(ops))
	}
	if ops[0].OperationName != "B" {
		t.Fatalf("name %q", ops[0].OperationName)
	}
	if string(ops[0].ResponseBody) != `{"data":{"b":2}}` {
		t.Fatalf("index-match wrong: %s", ops[0].ResponseBody)
	}
}

func TestExtractBatchResponseMismatchNilsResponses(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`[{"query":"query A{a}"},{"query":"query B{b}"}]`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{"a":1}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 2 {
		t.Fatalf("want 2, got %d", len(ops))
	}
	if ops[0].ResponseBody != nil || ops[1].ResponseBody != nil {
		t.Fatalf("mismatched batch must nil responses")
	}
}

func TestExtractGetTransport(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "GET", Host: "api.example.com",
		Path:           "/graphql?query=" + url.QueryEscape("query Ping{ping}") + "&operationName=Ping",
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{"ping":true}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 || ops[0].Transport != "get" || ops[0].OperationName != "Ping" {
		t.Fatalf("get transport: %+v", ops)
	}
}

func TestExtractMultiOpDocumentTypeFromExecuted(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"operationName":"DoIt","query":"query Look{a} mutation DoIt{b}"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 {
		t.Fatalf("want 1, got %d", len(ops))
	}
	if ops[0].OperationName != "DoIt" || ops[0].OperationType != "mutation" {
		t.Fatalf("multi-op type must come from executed decl, got %q/%q", ops[0].OperationName, ops[0].OperationType)
	}
}

func TestExtractNonGraphQLReturnsNil(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/users",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"name":"L","email":"l@example.com"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"id":1}`),
	}
	if ops := ExtractGraphQLOperations(flow); ops != nil {
		t.Fatalf("plain REST must yield nil, got %d", len(ops))
	}
}

func TestExtractShorthandQuery(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"query":"{me{name}}"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 || ops[0].OperationType != "query" || ops[0].OperationName != "" {
		t.Fatalf("shorthand: %+v", ops)
	}
}

func TestExtractMultipartSingle(t *testing.T) {
	body, ct := buildMultipart(t, `{"operationName":"Up","query":"mutation Up{up}"}`)
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": ct},
		RequestBody:    body,
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 {
		t.Fatalf("want 1, got %d", len(ops))
	}
	if ops[0].Transport != "multipart" {
		t.Fatalf("transport %q", ops[0].Transport)
	}
	if ops[0].OperationName != "Up" || ops[0].OperationType != "mutation" {
		t.Fatalf("name/type: %q/%q", ops[0].OperationName, ops[0].OperationType)
	}
}

func TestExtractMultipartBatch(t *testing.T) {
	body, ct := buildMultipart(t, `[{"operationName":"A","query":"mutation A{a}"},{"operationName":"B","query":"mutation B{b}"}]`)
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": ct},
		RequestBody:    body,
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 2 {
		t.Fatalf("want 2, got %d", len(ops))
	}
	if ops[0].Transport != "multipart" || ops[1].Transport != "multipart" {
		t.Fatalf("transport %q/%q", ops[0].Transport, ops[1].Transport)
	}
}

func TestExtractMultipartBatchSkipsNonGraphQLElements(t *testing.T) {
	body, ct := buildMultipart(t, `[{"foo":1},{"operationName":"B","query":"mutation B{b}"}]`)
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": ct},
		RequestBody:    body,
		ResponseStatus: 200,
		ResponseBody:   []byte(`[{"errors":[]},{"data":{"b":2}}]`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 {
		t.Fatalf("want 1 op (non-GraphQL element skipped), got %d", len(ops))
	}
	if ops[0].OperationName != "B" || ops[0].Transport != "multipart" {
		t.Fatalf("name/transport: %q/%q", ops[0].OperationName, ops[0].Transport)
	}
	if string(ops[0].ResponseBody) != `{"data":{"b":2}}` {
		t.Fatalf("index-match wrong: %s", ops[0].ResponseBody)
	}
}

func TestExtractMultipartBatchAllNonGraphQL(t *testing.T) {
	body, ct := buildMultipart(t, `[{"foo":1},{"bar":2}]`)
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": ct},
		RequestBody:    body,
		ResponseStatus: 200, ResponseBody: []byte(`[{},{}]`),
	}
	if ops := ExtractGraphQLOperations(flow); len(ops) != 0 {
		t.Fatalf("all-non-GraphQL batch must yield no ops, got %d", len(ops))
	}
}

func TestExtractSubscriptionType(t *testing.T) {
	flow := model.CapturedFlow{
		Method: "POST", Host: "api.example.com", Path: "/graphql",
		RequestHeaders: map[string]string{"content-type": "application/json"},
		RequestBody:    []byte(`{"query":"subscription OnPing{ping}"}`),
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 || ops[0].OperationType != "subscription" {
		t.Fatalf("subscription type: %+v", ops)
	}
}

func TestExtractPersistedHashViaGet(t *testing.T) {
	ext := url.QueryEscape(`{"persistedQuery":{"sha256Hash":"feedbeef"}}`)
	flow := model.CapturedFlow{
		Method: "GET", Host: "api.example.com",
		Path:           "/graphql?operationName=GetThing&extensions=" + ext,
		ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
	}
	ops := ExtractGraphQLOperations(flow)
	if len(ops) != 1 {
		t.Fatalf("want 1, got %d", len(ops))
	}
	if ops[0].Transport != "get" {
		t.Fatalf("transport %q", ops[0].Transport)
	}
	if ops[0].PersistedHash != "feedbeef" {
		t.Fatalf("hash %q", ops[0].PersistedHash)
	}
	if ops[0].OperationType != "unknown" {
		t.Fatalf("type %q (must not fabricate)", ops[0].OperationType)
	}
}

func TestExtractEmptyAndNonJSONReturnNil(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"non-json", "not json"},
		{"no-query-no-persisted", `{"foo":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flow := model.CapturedFlow{
				Method: "POST", Host: "api.example.com", Path: "/graphql",
				RequestHeaders: map[string]string{"content-type": "application/json"},
				RequestBody:    []byte(tc.body),
				ResponseStatus: 200, ResponseBody: []byte(`{"data":{}}`),
			}
			if ops := ExtractGraphQLOperations(flow); ops != nil {
				t.Fatalf("want nil, got %d ops", len(ops))
			}
		})
	}
}

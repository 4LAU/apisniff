// Package graphql extracts GraphQL operations from captured HTTP flows.
//
// It recognizes the four common GraphQL transports (single JSON object, JSON
// batch array, GET query string, and multipart form) without depending on a
// GraphQL parser: operation names and types are resolved with a regex over the
// query declaration prefix (requirement IR-8).
package graphql

import (
	"bytes"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"strings"

	"github.com/4LAU/apisniff/internal/model"
)

// Operation is one GraphQL operation observed in one flow. ExtractGraphQLOperations
// returns one Operation per executed operation (a batch yields several).
type Operation struct {
	Endpoint      string          // raw request URL (private use only — never emit publicly)
	Method        string          // upper-case HTTP method
	Transport     string          // "json" | "json-batch" | "get" | "multipart"
	OperationName string          // from transport, else parsed declaration, else ""
	OperationType string          // "query" | "mutation" | "subscription" | "unknown"
	Query         string          // raw query text; "" when persisted-hash only
	PersistedHash string          // sha256 from extensions.persistedQuery; "" when absent
	Variables     json.RawMessage // raw variables JSON; nil when absent
	ResponseBody  json.RawMessage // raw response JSON for this op; nil when unavailable/mismatched
	Status        int             // HTTP response status
}

// envelope is one decoded GraphQL request object (json/get/multipart share it).
type envelope struct {
	OperationName string          `json:"operationName"`
	Query         string          `json:"query"`
	Variables     json.RawMessage `json:"variables"`
	Extensions    json.RawMessage `json:"extensions"`
}

// declRe matches a named operation declaration: "query Foo", "mutation Bar(...)".
var declRe = regexp.MustCompile(`(?m)\b(query|mutation|subscription)\s+([A-Za-z_]\w*)`)

// ExtractGraphQLOperations returns the GraphQL operations carried by a flow, or
// nil if the flow is not GraphQL.
func ExtractGraphQLOperations(flow model.CapturedFlow) []Operation {
	switch classifyTransport(flow) {
	case "json", "json-batch":
		return extractJSONBody(flow)
	case "get":
		return extractGet(flow)
	case "multipart":
		return extractMultipart(flow)
	default:
		return nil
	}
}

// classifyTransport decides which GraphQL transport a flow uses, or "" if none.
func classifyTransport(flow model.CapturedFlow) string {
	if strings.EqualFold(flow.Method, "GET") {
		if isGraphQLQueryString(queryString(flow)) {
			return "get"
		}
		return ""
	}
	base := requestContentTypeBase(flow)
	switch base {
	case "multipart/form-data":
		return "multipart"
	case "application/json":
		return classifyJSONBody(flow.RequestBody)
	default:
		return ""
	}
}

// classifyJSONBody distinguishes a single object ("json") from a batch array
// ("json-batch"), requiring at least one element to look like a GraphQL request.
func classifyJSONBody(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var arr []envelope
		if json.Unmarshal(body, &arr) != nil || len(arr) == 0 {
			return ""
		}
		for _, e := range arr {
			if isGraphQLEnvelope(e) {
				return "json-batch"
			}
		}
		return ""
	}
	var e envelope
	if json.Unmarshal(body, &e) != nil || !isGraphQLEnvelope(e) {
		return ""
	}
	return "json"
}

// isGraphQLEnvelope reports whether a decoded object looks like a GraphQL
// request: it carries a query, or an operationName plus a persisted-query hash.
func isGraphQLEnvelope(e envelope) bool {
	if strings.TrimSpace(e.Query) != "" {
		return true
	}
	return e.OperationName != "" && readPersistedHash(e.Extensions) != ""
}

// extractJSONBody handles the json and json-batch transports.
func extractJSONBody(flow model.CapturedFlow) []Operation {
	if strings.HasPrefix(strings.TrimSpace(string(flow.RequestBody)), "[") {
		return extractBatch(flow.RequestBody, flow, "json-batch")
	}
	var e envelope
	if json.Unmarshal(flow.RequestBody, &e) != nil || !isGraphQLEnvelope(e) {
		return nil
	}
	return singleOp(e, flow, "json")
}

// singleOp builds the one-element Operation slice for a single-object transport,
// attaching the whole-flow response body.
func singleOp(e envelope, flow model.CapturedFlow, transport string) []Operation {
	op := operationFromEnvelope(e, flow, transport)
	op.ResponseBody = jsonOrNil(flow.ResponseBody)
	return []Operation{op}
}

// extractBatch decodes a request batch array (from requestBody) into one
// Operation per element, index-matching the response array; any response shape
// mismatch nils all responses. An empty or undecodable array yields nil.
func extractBatch(requestBody []byte, flow model.CapturedFlow, transport string) []Operation {
	var reqs []envelope
	if json.Unmarshal(requestBody, &reqs) != nil || len(reqs) == 0 {
		return nil
	}
	responses := batchResponses(flow.ResponseBody, len(reqs))
	ops := make([]Operation, 0, len(reqs))
	for i, e := range reqs {
		op := operationFromEnvelope(e, flow, transport)
		if responses != nil {
			op.ResponseBody = jsonOrNil(responses[i])
		}
		ops = append(ops, op)
	}
	return ops
}

// batchResponses returns the response-array elements when the response is an
// array of equal length, else nil (index-match cannot be trusted).
func batchResponses(body []byte, want int) []json.RawMessage {
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) != nil || len(arr) != want {
		return nil
	}
	return arr
}

// extractGet handles the GET query-string transport.
func extractGet(flow model.CapturedFlow) []Operation {
	values, err := url.ParseQuery(queryString(flow))
	if err != nil {
		return nil
	}
	e := envelope{
		OperationName: values.Get("operationName"),
		Query:         values.Get("query"),
		Variables:     rawJSONParam(values.Get("variables")),
		Extensions:    rawJSONParam(values.Get("extensions")),
	}
	return singleOp(e, flow, "get")
}

// extractMultipart parses the graphql-multipart-request "operations" field,
// which is a single object or an array, then treats it like json/json-batch.
func extractMultipart(flow model.CapturedFlow) []Operation {
	operations := multipartOperations(flow)
	if operations == nil {
		return nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(operations)), "[") {
		return extractBatch(operations, flow, "multipart")
	}
	var e envelope
	if json.Unmarshal(operations, &e) != nil || !isGraphQLEnvelope(e) {
		return nil
	}
	return singleOp(e, flow, "multipart")
}

// multipartOperations returns the raw "operations" form field, or nil.
func multipartOperations(flow model.CapturedFlow) []byte {
	_, params, err := mime.ParseMediaType(requestContentType(flow))
	if err != nil {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(flow.RequestBody), boundary)
	form, err := reader.ReadForm(1 << 20)
	if err != nil {
		return nil
	}
	defer form.RemoveAll()
	if vals := form.Value["operations"]; len(vals) > 0 {
		return []byte(vals[0])
	}
	return nil
}

// operationFromEnvelope builds an Operation from a decoded request envelope,
// resolving the name and type and reading any persisted-query hash.
func operationFromEnvelope(e envelope, flow model.CapturedFlow, transport string) Operation {
	query := strings.TrimSpace(e.Query)
	hash := readPersistedHash(e.Extensions)
	name, opType := resolveNameType(query, e.OperationName)
	return Operation{
		Endpoint:      flow.URL,
		Method:        strings.ToUpper(flow.Method),
		Transport:     transport,
		OperationName: name,
		OperationType: opType,
		Query:         query,
		PersistedHash: hash,
		Variables:     jsonOrNil(e.Variables),
		Status:        flow.ResponseStatus,
	}
}

// resolveNameType resolves OperationName and OperationType from the query text
// and the transport-provided executed name, per the IR-8 resolution order.
//
// Known limitation (by design): there is no GraphQL parser, so the regex match
// is purely lexical. A "#"-commented decoy declaration (e.g. "# mutation Foo")
// whose name matches the executed operationName can mis-resolve the type. This
// is acceptable for real captured traffic, where such decoys do not occur.
func resolveNameType(query, executedName string) (string, string) {
	if query == "" {
		return executedName, "unknown"
	}
	decls := declRe.FindAllStringSubmatch(query, -1)
	if executedName != "" {
		for _, d := range decls {
			if d[2] == executedName {
				return executedName, d[1]
			}
		}
	}
	if len(decls) == 1 {
		return decls[0][2], decls[0][1]
	}
	if strings.HasPrefix(query, "{") {
		return executedName, "query"
	}
	return executedName, "unknown"
}

// readPersistedHash returns extensions.persistedQuery.sha256Hash, or "".
func readPersistedHash(extensions json.RawMessage) string {
	if len(extensions) == 0 {
		return ""
	}
	var ext struct {
		PersistedQuery struct {
			SHA256Hash string `json:"sha256Hash"`
		} `json:"persistedQuery"`
	}
	if json.Unmarshal(extensions, &ext) != nil {
		return ""
	}
	return ext.PersistedQuery.SHA256Hash
}

// isGraphQLQueryString reports whether a GET query string carries a GraphQL
// request: a query= param, or operationName= together with extensions=.
func isGraphQLQueryString(qs string) bool {
	if qs == "" {
		return false
	}
	values, err := url.ParseQuery(qs)
	if err != nil {
		return false
	}
	if values.Get("query") != "" {
		return true
	}
	return values.Get("operationName") != "" && values.Get("extensions") != ""
}

// queryString returns the raw query string from the flow path or URL.
func queryString(flow model.CapturedFlow) string {
	if _, qs, ok := strings.Cut(flow.Path, "?"); ok {
		return qs
	}
	if _, qs, ok := strings.Cut(flow.URL, "?"); ok {
		return qs
	}
	return ""
}

// requestContentType returns the raw request content-type header.
func requestContentType(flow model.CapturedFlow) string {
	return model.GetHeader(flow.RequestHeaders, "content-type")
}

// requestContentTypeBase returns the lower-cased media type without parameters.
func requestContentTypeBase(flow model.CapturedFlow) string {
	ct := requestContentType(flow)
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}

// rawJSONParam returns a query-string param as raw JSON, or nil when empty or
// not valid JSON.
func rawJSONParam(value string) json.RawMessage {
	if value == "" {
		return nil
	}
	return jsonOrNil([]byte(value))
}

// jsonOrNil returns body as RawMessage when it is non-empty valid JSON, else nil.
func jsonOrNil(body []byte) json.RawMessage {
	if len(body) == 0 || !json.Valid(body) {
		return nil
	}
	return json.RawMessage(body)
}

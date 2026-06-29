package spec

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/graphql"
	"github.com/4LAU/apisniff/internal/jsonschema"
	"github.com/4LAU/apisniff/internal/model"
	"gopkg.in/yaml.v3"
)

var apiContentTypes = map[string]struct{}{
	"application/json":                  {},
	"application/x-www-form-urlencoded": {},
	"multipart/form-data":               {},
}

type Options struct {
	InferSchemes    bool
	IncludeExamples bool
}

var ErrNoValidAPIFlows = errors.New("no valid API flows for spec generation")

type queryEvidence struct {
	presentCount int
	values       map[string]struct{}
}

type observedOperation struct {
	path            string
	method          string
	flows           []model.CapturedFlow
	pathParamNames  []string
	pathParamValues map[string][]string
	query           map[string]*queryEvidence
	requestSchemas  map[string]map[string]any
	responseSchemas map[responseSchemaKey]map[string]any
	graphqlOps      []gqlOpRef
	restFlowCount   int
}

// gqlOpRef holds only normalized GraphQL identity — safe to emit by
// construction. It never carries raw URLs or variable values.
type gqlOpRef struct {
	host   string // normalized: strings.ToLower + TrimSuffix(".")
	path   string // model.NormalizeSpecPath output (already computed for the bucket)
	name   string
	opType string
	source string // captured-query | persisted-hash
}

type responseSchemaKey struct {
	status      string
	contentType string
}

type componentUse struct {
	path   string
	media  map[string]any
	schema map[string]any
}

type componentCandidateKey struct {
	context     string
	fingerprint string
}

func IsAPIFlow(flow model.CapturedFlow) bool {
	if strings.Contains(flow.ContentType(), "json") {
		return true
	}
	reqCT := contentTypeBase(model.GetHeader(flow.RequestHeaders, "content-type"))
	_, ok := apiContentTypes[reqCT]
	return ok
}

func Generate(flows []model.CapturedFlow, domain string, patterns []auth.Pattern, opts Options) (map[string]any, error) {
	host := targetHost(domain)
	operations := aggregateOperations(flows, opts.IncludeExamples)
	if len(operations) == 0 {
		return nil, ErrNoValidAPIFlows
	}
	operationIDs := operationIDs(operations)
	paths := map[string]any{}

	for _, op := range operations {
		operation := buildOperationMetadata(op, operationIDs[operationKey(op)])
		parameters := append(buildPathParams(op), buildQueryParams(op)...)
		if len(parameters) > 0 {
			operation["parameters"] = parameters
		}
		hasGQL := len(op.graphqlOps) > 0
		mixed := hasGQL && op.restFlowCount > 0
		switch {
		case !hasGQL:
			if requestBody := buildRequestBody(op); requestBody != nil {
				operation["requestBody"] = requestBody
			}
			operation["responses"] = buildResponses(op)
		case !mixed:
			operation["requestBody"] = graphqlRequestBody()
			operation["responses"] = graphqlResponses(op)
		default:
			if requestBody := buildRequestBody(op); requestBody != nil {
				wrapContentSchemas(asMap(requestBody["content"]), graphqlRequestEnvelopeRef())
				operation["requestBody"] = requestBody
			} else {
				operation["requestBody"] = graphqlRequestBody()
			}
			responses := buildResponses(op)
			for _, responseValue := range responses {
				wrapContentSchemas(asMap(asMap(responseValue)["content"]), graphqlResponseEnvelopeRef())
			}
			operation["responses"] = responses
		}
		if hasGQL {
			operation["x-apisniff-graphql"] = buildGraphQLExtension(op, mixed)
		}

		pathItem := asMap(paths[op.path])
		pathItem[op.method] = operation
		paths[op.path] = pathItem
	}

	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       host + " API",
			"version":     "0.1.0",
			"description": "Auto-generated from captured traffic for " + domain,
		},
		"servers": []any{map[string]any{"url": "https://" + host}},
		"paths":   paths,
	}
	addAuth(doc, patterns, opts.InferSchemes)
	promoteComponents(doc, operations)
	registerGraphQLEnvelopes(doc, operations)
	return doc, nil
}

func aggregateOperations(flows []model.CapturedFlow, includeExamples bool) []*observedOperation {
	type groupKey struct {
		path   string
		method string
	}
	operations := map[groupKey]*observedOperation{}
	for _, flow := range flows {
		if flow.ResponseStatus < 100 || flow.ResponseStatus > 599 {
			continue
		}
		method := strings.ToLower(flow.Method)
		if !isOpenAPIOperation(method) {
			continue
		}
		path, pathParams, ok := model.NormalizeSpecPath(flow.Path)
		if !ok {
			continue
		}
		key := groupKey{path: path, method: method}
		op := operations[key]
		if op == nil {
			op = &observedOperation{
				path:            path,
				method:          method,
				pathParamValues: map[string][]string{},
				query:           map[string]*queryEvidence{},
				requestSchemas:  map[string]map[string]any{},
				responseSchemas: map[responseSchemaKey]map[string]any{},
			}
			seenParams := map[string]struct{}{}
			for _, param := range pathParams {
				if _, ok := seenParams[param.Name]; ok {
					continue
				}
				op.pathParamNames = append(op.pathParamNames, param.Name)
				seenParams[param.Name] = struct{}{}
			}
			operations[key] = op
		}
		op.flows = append(op.flows, flow)
		for _, param := range pathParams {
			if param.ObservedValue != "" {
				op.pathParamValues[param.Name] = append(op.pathParamValues[param.Name], param.ObservedValue)
			}
		}
		if _, rawQuery, ok := strings.Cut(flow.Path, "?"); ok {
			values, _ := url.ParseQuery(rawQuery)
			for name, paramValues := range values {
				if name == "" {
					continue
				}
				evidence := op.query[name]
				if evidence == nil {
					evidence = &queryEvidence{values: map[string]struct{}{}}
					op.query[name] = evidence
				}
				evidence.presentCount++
				for _, value := range paramValues {
					evidence.values[value] = struct{}{}
				}
			}
		}
		if gqlOps := graphql.ExtractGraphQLOperations(flow); len(gqlOps) > 0 {
			for _, g := range gqlOps {
				source := "captured-query"
				if g.PersistedHash != "" && g.Query == "" {
					source = "persisted-hash"
				}
				op.graphqlOps = append(op.graphqlOps, gqlOpRef{
					host:   normalizeHost(flow.Host),
					path:   path,
					name:   g.OperationName,
					opType: g.OperationType,
					source: source,
				})
			}
		} else {
			op.restFlowCount++
			recordRequestSchema(op, flow, includeExamples)
			recordResponseSchema(op, flow, includeExamples)
		}
	}

	keys := make([]groupKey, 0, len(operations))
	for key := range operations {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path == keys[j].path {
			return keys[i].method < keys[j].method
		}
		return keys[i].path < keys[j].path
	})

	out := make([]*observedOperation, 0, len(keys))
	for _, key := range keys {
		out = append(out, operations[key])
	}
	return out
}

var openAPIOperations = map[string]struct{}{
	"get":     {},
	"put":     {},
	"post":    {},
	"delete":  {},
	"options": {},
	"head":    {},
	"patch":   {},
	"trace":   {},
}

func isOpenAPIOperation(method string) bool {
	_, ok := openAPIOperations[method]
	return ok
}

func recordRequestSchema(op *observedOperation, flow model.CapturedFlow, includeExamples bool) {
	if op.method != "post" && op.method != "put" && op.method != "patch" {
		return
	}
	if len(flow.RequestBody) == 0 {
		return
	}
	rawCT := model.GetHeader(flow.RequestHeaders, "content-type")
	ct := contentTypeBase(rawCT)
	var schema map[string]any
	switch ct {
	case "application/json":
		if parsed := jsonschema.ParseJSONBody(flow.RequestBody); parsed != nil {
			schema = jsonschema.InferSchema(parsed, includeExamples, "")
		}
	case "application/x-www-form-urlencoded":
		if parsed := ParseFormURLEncoded(flow.RequestBody); parsed != nil {
			schema = jsonschema.InferSchema(parsed, includeExamples, "")
		}
	case "multipart/form-data":
		if parsed := ParseMultipart(flow.RequestBody, rawCT); parsed != nil {
			props := map[string]any{}
			for key, value := range parsed {
				if value == jsonschema.FileSentinel {
					props[key] = map[string]any{"type": "string", "format": "binary"}
				} else {
					props[key] = jsonschema.InferSchema(value, includeExamples, key)
				}
			}
			schema = map[string]any{"type": "object", "properties": props}
		}
	}
	if schema == nil {
		return
	}
	if existing, ok := op.requestSchemas[ct]; ok {
		op.requestSchemas[ct] = jsonschema.MergeSchemas(existing, schema)
	} else {
		op.requestSchemas[ct] = schema
	}
}

func recordResponseSchema(op *observedOperation, flow model.CapturedFlow, includeExamples bool) {
	ct := flow.ContentType()
	if ct == "" {
		ct = "application/json"
	}
	key := responseSchemaKey{status: intString(flow.ResponseStatus), contentType: ct}
	if !isJSONishContentType(ct) {
		// Non-JSON payloads (HTML, XML, CSV, plain text, …) can't be
		// schematized, but the endpoint is real. Record the media type with a
		// nil schema so the spec documents that it exists and what it returns,
		// without inventing structure. A nil entry never overwrites a real
		// schema recorded for the same status+content-type.
		if _, ok := op.responseSchemas[key]; !ok {
			op.responseSchemas[key] = nil
		}
		return
	}
	parsed := jsonschema.ParseJSONBody(flow.ResponseBody)
	if parsed == nil {
		return
	}
	schema := jsonschema.InferSchema(parsed, includeExamples, "")
	if existing, ok := op.responseSchemas[key]; ok && existing != nil {
		op.responseSchemas[key] = jsonschema.MergeSchemas(existing, schema)
	} else {
		op.responseSchemas[key] = schema
	}
}

func buildPathParams(op *observedOperation) []any {
	params := make([]any, 0, len(op.pathParamNames))
	for _, name := range op.pathParamNames {
		params = append(params, map[string]any{
			"name":     name,
			"in":       "path",
			"required": true,
			"schema":   map[string]any{"type": inferPrimitiveType(op.pathParamValues[name])},
		})
	}
	return params
}

func buildQueryParams(op *observedOperation) []any {
	names := make([]string, 0, len(op.query))
	for name := range op.query {
		names = append(names, name)
	}
	sort.Strings(names)
	params := make([]any, 0, len(names))
	for _, name := range names {
		evidence := op.query[name]
		values := make([]string, 0, len(evidence.values))
		for value := range evidence.values {
			values = append(values, value)
		}
		inferredType := inferPrimitiveType(values)
		params = append(params, map[string]any{
			"name":     name,
			"in":       "query",
			"required": false,
			"schema":   map[string]any{"type": inferredType},
			"x-apisniff-observed": map[string]any{
				"present_count":        evidence.presentCount,
				"total_count":          len(op.flows),
				"distinct_value_count": len(evidence.values),
				"inferred_type":        inferredType,
				"confidence":           "observed",
			},
		})
	}
	return params
}

func buildRequestBody(op *observedOperation) map[string]any {
	if len(op.requestSchemas) == 0 {
		return nil
	}
	content := map[string]any{}
	contentTypes := make([]string, 0, len(op.requestSchemas))
	for ct := range op.requestSchemas {
		contentTypes = append(contentTypes, ct)
	}
	sort.Strings(contentTypes)
	for _, ct := range contentTypes {
		content[ct] = map[string]any{"schema": op.requestSchemas[ct]}
	}
	return map[string]any{"content": content}
}

func buildResponses(op *observedOperation) map[string]any {
	statuses := map[string]struct{}{}
	for _, flow := range op.flows {
		statuses[intString(flow.ResponseStatus)] = struct{}{}
	}
	statusKeys := make([]string, 0, len(statuses))
	for status := range statuses {
		statusKeys = append(statusKeys, status)
	}
	sort.Slice(statusKeys, func(i, j int) bool {
		iInt, iErr := strconv.Atoi(statusKeys[i])
		jInt, jErr := strconv.Atoi(statusKeys[j])
		if iErr == nil && jErr == nil && iInt != jInt {
			return iInt < jInt
		}
		if iErr == nil && jErr != nil {
			return true
		}
		if iErr != nil && jErr == nil {
			return false
		}
		return statusKeys[i] < statusKeys[j]
	})
	responses := map[string]any{}
	for _, status := range statusKeys {
		responses[status] = map[string]any{"description": statusDescription(status)}
	}

	responseKeys := make([]responseSchemaKey, 0, len(op.responseSchemas))
	for key := range op.responseSchemas {
		responseKeys = append(responseKeys, key)
	}
	sort.Slice(responseKeys, func(i, j int) bool {
		if responseKeys[i].status == responseKeys[j].status {
			return responseKeys[i].contentType < responseKeys[j].contentType
		}
		return responseKeys[i].status < responseKeys[j].status
	})
	for _, key := range responseKeys {
		response := asMap(responses[key.status])
		if len(response) == 0 {
			response = map[string]any{"description": statusDescription(key.status)}
		}
		content := asMap(response["content"])
		media := map[string]any{}
		if schema := op.responseSchemas[key]; schema != nil {
			media["schema"] = schema
		}
		content[key.contentType] = media
		response["content"] = content
		responses[key.status] = response
	}
	if len(responses) == 0 {
		responses["default"] = map[string]any{"description": "Observed response"}
	}
	return responses
}

func graphqlRequestEnvelopeRef() map[string]any {
	return map[string]any{"$ref": "#/components/schemas/GraphQLRequestEnvelope"}
}

func graphqlResponseEnvelopeRef() map[string]any {
	return map[string]any{"$ref": "#/components/schemas/GraphQLResponseEnvelope"}
}

// graphqlRequestBody is the generic request body for a pure-GraphQL endpoint.
func graphqlRequestBody() map[string]any {
	return map[string]any{
		"content": map[string]any{
			"application/json": map[string]any{"schema": graphqlRequestEnvelopeRef()},
		},
	}
}

// graphqlResponses builds responses for a pure-GraphQL endpoint: a 200 whose
// JSON schema is the response envelope, plus any other observed status codes
// kept description-only.
func graphqlResponses(op *observedOperation) map[string]any {
	responses := map[string]any{}
	for _, flow := range op.flows {
		status := intString(flow.ResponseStatus)
		if status == "200" {
			continue
		}
		responses[status] = map[string]any{"description": statusDescription(status)}
	}
	responses["200"] = map[string]any{
		"description": statusDescription("200"),
		"content": map[string]any{
			"application/json": map[string]any{"schema": graphqlResponseEnvelopeRef()},
		},
	}
	return responses
}

// wrapContentSchemas rewrites each content media-type's schema to a oneOf of
// the existing REST schema and the supplied envelope ref. Fresh maps per use
// avoid yaml.v3 anchor sharing.
func wrapContentSchemas(content map[string]any, envelopeRef map[string]any) {
	for _, mediaValue := range content {
		media := asMap(mediaValue)
		restSchema := media["schema"]
		if restSchema == nil {
			continue
		}
		ref := map[string]any{}
		for k, v := range envelopeRef {
			ref[k] = v
		}
		media["schema"] = map[string]any{"oneOf": []any{restSchema, ref}}
	}
}

// buildGraphQLExtension produces the share-safe x-apisniff-graphql value:
// endpoints grouped by {host, path}, each with distinct {name, type, source}
// operations. It carries no raw URLs and no variable values.
func buildGraphQLExtension(op *observedOperation, mixed bool) map[string]any {
	type endpointKey struct{ host, path string }
	type opKey struct{ name, opType, source string }
	order := []endpointKey{}
	grouped := map[endpointKey]map[opKey]struct{}{}
	for _, g := range op.graphqlOps {
		ek := endpointKey{host: g.host, path: g.path}
		ops, ok := grouped[ek]
		if !ok {
			ops = map[opKey]struct{}{}
			grouped[ek] = ops
			order = append(order, ek)
		}
		ops[opKey{name: g.name, opType: g.opType, source: g.source}] = struct{}{}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].host == order[j].host {
			return order[i].path < order[j].path
		}
		return order[i].host < order[j].host
	})
	endpoints := make([]any, 0, len(order))
	for _, ek := range order {
		opKeys := make([]opKey, 0, len(grouped[ek]))
		for k := range grouped[ek] {
			opKeys = append(opKeys, k)
		}
		sort.Slice(opKeys, func(i, j int) bool {
			if opKeys[i].name == opKeys[j].name {
				return opKeys[i].source < opKeys[j].source
			}
			return opKeys[i].name < opKeys[j].name
		})
		operations := make([]any, 0, len(opKeys))
		for _, k := range opKeys {
			operations = append(operations, map[string]any{
				"name":   k.name,
				"type":   k.opType,
				"source": k.source,
			})
		}
		endpoints = append(endpoints, map[string]any{
			"host":       ek.host,
			"path":       ek.path,
			"operations": operations,
		})
	}
	return map[string]any{
		"catalog":   "graphql-operations.json",
		"mixed":     mixed,
		"endpoints": endpoints,
	}
}

// registerGraphQLEnvelopes adds the generic GraphQL request/response envelope
// component schemas when any operation carries GraphQL traffic.
func registerGraphQLEnvelopes(doc map[string]any, operations []*observedOperation) {
	hasGQL := false
	for _, op := range operations {
		if len(op.graphqlOps) > 0 {
			hasGQL = true
			break
		}
	}
	if !hasGQL {
		return
	}
	components := asMap(doc["components"])
	schemas := asMap(components["schemas"])
	schemas["GraphQLRequestEnvelope"] = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query":         map[string]any{"type": "string"},
			"operationName": map[string]any{"type": "string"},
			"variables":     map[string]any{"type": "object"},
			"extensions":    map[string]any{"type": "object"},
		},
	}
	schemas["GraphQLResponseEnvelope"] = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"data":   map[string]any{"type": "object"},
			"errors": map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		},
	}
	components["schemas"] = schemas
	doc["components"] = components
}

func buildOperationMetadata(op *observedOperation, operationID string) map[string]any {
	hosts := map[string]struct{}{}
	methods := map[string]struct{}{}
	statusCodes := map[int]struct{}{}
	contentTypes := map[string]struct{}{}
	for _, flow := range op.flows {
		if flow.Host != "" {
			hosts[strings.ToLower(strings.TrimSuffix(flow.Host, "."))] = struct{}{}
		}
		methods[strings.ToUpper(flow.Method)] = struct{}{}
		statusCodes[flow.ResponseStatus] = struct{}{}
		if ct := flow.ContentType(); ct != "" {
			contentTypes[ct] = struct{}{}
		}
	}
	return map[string]any{
		"operationId": operationID,
		"tags":        []any{operationTag(op.path)},
		"x-apisniff-observed": map[string]any{
			"flow_count":    len(op.flows),
			"hosts":         sortedStringSet(hosts),
			"methods":       sortedStringSet(methods),
			"status_codes":  sortedIntSet(statusCodes),
			"content_types": sortedStringSet(contentTypes),
		},
	}
}

var (
	intValueRe     = regexp.MustCompile(`^[+-]?\d+$`)
	numberValueRe  = regexp.MustCompile(`^[+-]?(\d+\.\d+|\d+|\.\d+)$`)
	versionSegment = regexp.MustCompile(`(?i)^v\d+$`)
	simpleIdentRe  = regexp.MustCompile(`^[A-Za-z][0-9A-Za-z]*$`)
)

var genericTagPrefixes = map[string]struct{}{
	"api":  {},
	"rest": {},
	"rpc":  {},
}

func inferPrimitiveType(values []string) string {
	if len(values) == 0 {
		return "string"
	}
	allBool := true
	allInt := true
	allNumber := true
	for _, value := range values {
		lower := strings.ToLower(value)
		if lower != "true" && lower != "false" {
			allBool = false
		}
		if !intValueRe.MatchString(value) {
			allInt = false
		}
		if !numberValueRe.MatchString(value) {
			allNumber = false
		}
	}
	switch {
	case allBool:
		return "boolean"
	case allInt:
		return "integer"
	case allNumber:
		return "number"
	default:
		return "string"
	}
}

func operationIDs(operations []*observedOperation) map[string]string {
	bases := map[string]string{}
	counts := map[string]int{}
	for _, op := range operations {
		key := operationKey(op)
		base := operationIDBase(op.method, op.path)
		bases[key] = base
		counts[base]++
	}
	out := map[string]string{}
	for _, op := range operations {
		key := operationKey(op)
		base := bases[key]
		if counts[base] == 1 {
			out[key] = base
			continue
		}
		sum := sha1.Sum([]byte(op.method + " " + op.path))
		out[key] = base + "_" + fmt.Sprintf("%x", sum)[:8]
	}
	return out
}

func operationKey(op *observedOperation) string {
	return op.path + "\x00" + op.method
}

func operationIDBase(method, path string) string {
	parts := []string{strings.ToLower(method)}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" {
			continue
		}
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			parts = append(parts, "by", strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}"))
		} else {
			parts = append(parts, segment)
		}
	}
	first := model.CamelName(parts[0])
	for _, part := range parts[1:] {
		first += pascalName(part)
	}
	return first
}

func operationTag(path string) string {
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || strings.HasPrefix(segment, "{") {
			continue
		}
		if _, ok := genericTagPrefixes[strings.ToLower(segment)]; ok || versionSegment.MatchString(segment) {
			continue
		}
		return model.SingularizeSegment(segment)
	}
	return "default"
}

func targetHost(value string) string {
	raw := value
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		return cleanServerHost(parsed.Hostname())
	}
	hostSource := value
	if _, afterScheme, ok := strings.Cut(value, "://"); ok {
		hostSource = afterScheme
	}
	host := strings.SplitN(hostSource, "/", 2)[0]
	return cleanServerHost(host)
}

func cleanServerHost(host string) string {
	cleaned := strings.NewReplacer("{", "", "}", "").Replace(host)
	cleaned = strings.ToLower(strings.TrimSuffix(cleaned, "."))
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

func statusDescription(status string) string {
	code, err := strconv.Atoi(status)
	if err != nil {
		return "Observed response"
	}
	if text := http.StatusText(code); text != "" {
		return text
	}
	return "Observed response"
}

func isJSONishContentType(contentType string) bool {
	return strings.Contains(contentType, "json")
}

func sortedStringSet(values map[string]struct{}) []any {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, key)
	}
	return out
}

func sortedIntSet(values map[int]struct{}) []any {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, key)
	}
	return out
}

func schemaFingerprint(schema map[string]any) string {
	data, _ := json.Marshal(schema)
	return string(data)
}

func componentBaseName(path, context string) string {
	staticSegments := []string{}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || strings.HasPrefix(segment, "{") {
			continue
		}
		if _, ok := genericTagPrefixes[strings.ToLower(segment)]; ok || versionSegment.MatchString(segment) {
			continue
		}
		staticSegments = append(staticSegments, segment)
	}
	resource := "Observed"
	if len(staticSegments) > 0 {
		resource = model.SingularizeSegment(staticSegments[len(staticSegments)-1])
	}
	return pascalName(resource) + context
}

func uniqueComponentName(base string, used map[string]struct{}) string {
	candidate := base
	for counter := 2; ; counter++ {
		if _, ok := used[candidate]; !ok {
			used[candidate] = struct{}{}
			return candidate
		}
		candidate = base + strconv.Itoa(counter)
	}
}

func promoteComponents(doc map[string]any, operations []*observedOperation) {
	candidates := map[componentCandidateKey][]componentUse{}
	for _, op := range operations {
		opDict := asMap(asMap(asMap(doc["paths"])[op.path])[op.method])
		requestBody := asMap(opDict["requestBody"])
		for _, mediaValue := range asMap(requestBody["content"]) {
			media := asMap(mediaValue)
			schema := asMap(media["schema"])
			if schema["type"] == "object" || schema["type"] == "array" {
				key := componentCandidateKey{context: "Request", fingerprint: schemaFingerprint(schema)}
				candidates[key] = append(candidates[key], componentUse{path: op.path, media: media, schema: schema})
			}
		}
		for _, responseValue := range asMap(opDict["responses"]) {
			response := asMap(responseValue)
			for _, mediaValue := range asMap(response["content"]) {
				media := asMap(mediaValue)
				schema := asMap(media["schema"])
				if schema["type"] == "object" || schema["type"] == "array" {
					key := componentCandidateKey{context: "Response", fingerprint: schemaFingerprint(schema)}
					candidates[key] = append(candidates[key], componentUse{path: op.path, media: media, schema: schema})
				}
			}
		}
	}

	keys := make([]componentCandidateKey, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].context == keys[j].context {
			return keys[i].fingerprint < keys[j].fingerprint
		}
		return keys[i].context < keys[j].context
	})
	schemas := map[string]any{}
	usedNames := map[string]struct{}{}
	for _, key := range keys {
		uses := candidates[key]
		if len(uses) < 2 {
			continue
		}
		name := uniqueComponentName(componentBaseName(uses[0].path, key.context), usedNames)
		schemas[name] = uses[0].schema
		for _, use := range uses {
			// Fresh map per use: yaml.v3 emits anchors for shared instances.
			use.media["schema"] = map[string]any{"$ref": "#/components/schemas/" + name}
		}
	}
	if len(schemas) == 0 {
		return
	}
	components := asMap(doc["components"])
	components["schemas"] = schemas
	doc["components"] = components
}

func pascalName(value string) string {
	if simpleIdentRe.MatchString(value) && strings.IndexFunc(value, func(r rune) bool {
		return r >= 'A' && r <= 'Z'
	}) >= 0 {
		return strings.ToUpper(value[:1]) + value[1:]
	}
	camel := model.CamelName(value)
	if camel == "" {
		return "Value"
	}
	return strings.ToUpper(camel[:1]) + camel[1:]
}

func addAuth(doc map[string]any, patterns []auth.Pattern, infer bool) {
	if len(patterns) == 0 {
		return
	}
	var observed []any
	var tokenEndpoints []any
	schemes := map[string]any{}
	for _, pattern := range patterns {
		observed = append(observed, map[string]any{"type": pattern.AuthType, "detail": pattern.Detail, "flow_count": pattern.FlowCount})
		switch pattern.AuthType {
		case "token_endpoint":
			tokenEndpoints = append(tokenEndpoints, pattern.Detail)
		case "bearer":
			if infer {
				schemes["bearer"] = map[string]any{"type": "http", "scheme": "bearer"}
			}
		case "basic":
			if infer {
				schemes["basic"] = map[string]any{"type": "http", "scheme": "basic"}
			}
		case "api_key_header":
			if infer {
				schemes["api_key_header"] = map[string]any{"type": "apiKey", "in": "header", "name": pattern.Detail}
			}
		case "api_key_query":
			if infer {
				schemes["api_key_query"] = map[string]any{"type": "apiKey", "in": "query", "name": pattern.Detail}
			}
		case "session_cookie":
			if infer {
				schemes["session_cookie"] = map[string]any{"type": "apiKey", "in": "cookie", "name": pattern.Detail}
			}
		}
	}
	doc["x-observed-auth"] = observed
	if len(tokenEndpoints) > 0 {
		doc["x-observed-token-endpoints"] = tokenEndpoints
	}
	if len(schemes) > 0 {
		doc["components"] = map[string]any{"securitySchemes": schemes}
	}
}

func Marshal(doc map[string]any, format string) ([]byte, error) {
	if format == "json" {
		return json.MarshalIndent(doc, "", "  ")
	}
	return yaml.Marshal(doc)
}

func FilterAPIFlows(flows []model.CapturedFlow) []model.CapturedFlow {
	out := make([]model.CapturedFlow, 0, len(flows))
	for _, flow := range flows {
		if IsAPIFlow(flow) || hasTag(flow, includedForSpecTag) || hasCategoryTag(flow, "business_api") || hasCategoryTag(flow, "auth") || hasCategoryTag(flow, "antibot") {
			out = append(out, flow)
		}
	}
	return out
}

func hasCategoryTag(flow model.CapturedFlow, category string) bool {
	return hasTag(flow, "category:"+category)
}

func hasTag(flow model.CapturedFlow, want string) bool {
	for _, tag := range flow.Tags {
		if tag == want {
			return true
		}
	}
	return false
}

func contentTypeBase(value string) string {
	return strings.TrimSpace(strings.ToLower(strings.SplitN(value, ";", 2)[0]))
}

func intString(value int) string {
	return strconv.Itoa(value)
}

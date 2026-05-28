package spec

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/4LAU/apisniff/internal/auth"
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
}

type responseSchemaKey struct {
	status      string
	contentType string
}

type componentUse struct {
	path   string
	method string
	key    string
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

func Generate(flows []model.CapturedFlow, domain string, patterns []auth.Pattern, opts Options) map[string]any {
	host := targetHost(domain)
	operations := aggregateOperations(flows, opts.IncludeExamples)
	operationIDs := operationIDs(operations)
	paths := map[string]any{}

	for _, op := range operations {
		operation := buildOperationMetadata(op, operationIDs[operationKey(op)])
		parameters := append(buildPathParams(op), buildQueryParams(op)...)
		if len(parameters) > 0 {
			operation["parameters"] = parameters
		}
		if requestBody := buildRequestBody(op); requestBody != nil {
			operation["requestBody"] = requestBody
		}
		operation["responses"] = buildResponses(op)

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
	return doc
}

func aggregateOperations(flows []model.CapturedFlow, includeExamples bool) []*observedOperation {
	type groupKey struct {
		path   string
		method string
	}
	operations := map[groupKey]*observedOperation{}
	for _, flow := range flows {
		path, pathParams := model.NormalizePathWithParams(flow.Path)
		method := strings.ToLower(flow.Method)
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
			op.pathParamValues[param.Name] = append(op.pathParamValues[param.Name], param.ObservedValue)
		}
		if _, rawQuery, ok := strings.Cut(flow.Path, "?"); ok {
			values, _ := url.ParseQuery(rawQuery)
			for name, paramValues := range values {
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
		recordRequestSchema(op, flow, includeExamples)
		recordResponseSchema(op, flow, includeExamples)
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
		if parsed := ParseJSONBody(flow.RequestBody); parsed != nil {
			schema = InferSchema(parsed, includeExamples, "")
		}
	case "application/x-www-form-urlencoded":
		if parsed := ParseFormURLEncoded(flow.RequestBody); parsed != nil {
			schema = InferSchema(parsed, includeExamples, "")
		}
	case "multipart/form-data":
		if parsed := ParseMultipart(flow.RequestBody, rawCT); parsed != nil {
			props := map[string]any{}
			for key, value := range parsed {
				if value == fileSentinel {
					props[key] = map[string]any{"type": "string", "format": "binary"}
				} else {
					props[key] = InferSchema(value, includeExamples, key)
				}
			}
			schema = map[string]any{"type": "object", "properties": props}
		}
	}
	if schema == nil {
		return
	}
	if existing, ok := op.requestSchemas[ct]; ok {
		op.requestSchemas[ct] = MergeSchemas(existing, schema)
	} else {
		op.requestSchemas[ct] = schema
	}
}

func recordResponseSchema(op *observedOperation, flow model.CapturedFlow, includeExamples bool) {
	ct := flow.ContentType()
	if ct == "" {
		ct = "application/json"
	}
	if !isJSONishContentType(ct) {
		return
	}
	parsed := ParseJSONBody(flow.ResponseBody)
	if parsed == nil {
		return
	}
	key := responseSchemaKey{status: intString(flow.ResponseStatus), contentType: ct}
	schema := InferSchema(parsed, includeExamples, "")
	if existing, ok := op.responseSchemas[key]; ok {
		op.responseSchemas[key] = MergeSchemas(existing, schema)
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
		content[key.contentType] = map[string]any{"schema": op.responseSchemas[key]}
		response["content"] = content
		responses[key.status] = response
	}
	if len(responses) == 0 {
		responses["default"] = map[string]any{"description": "Observed response"}
	}
	return responses
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
	intValueRe      = regexp.MustCompile(`^[+-]?\d+$`)
	numberValueRe   = regexp.MustCompile(`^[+-]?(\d+\.\d+|\d+|\.\d+)$`)
	versionSegment  = regexp.MustCompile(`(?i)^v\d+$`)
	simpleIdentRe   = regexp.MustCompile(`^[A-Za-z][0-9A-Za-z]*$`)
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
		return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}
	host := strings.SplitN(value, "/", 2)[0]
	return strings.ToLower(strings.TrimSuffix(host, "."))
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
	return contentType == "application/json" || strings.HasSuffix(contentType, "+json") || strings.Contains(contentType, "json")
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
		for ct, mediaValue := range asMap(requestBody["content"]) {
			media := asMap(mediaValue)
			schema := asMap(media["schema"])
			if schema["type"] == "object" || schema["type"] == "array" {
				key := componentCandidateKey{context: "Request", fingerprint: schemaFingerprint(schema)}
				candidates[key] = append(candidates[key], componentUse{path: op.path, method: op.method, key: ct, schema: schema})
			}
		}
		for status, responseValue := range asMap(opDict["responses"]) {
			response := asMap(responseValue)
			for ct, mediaValue := range asMap(response["content"]) {
				media := asMap(mediaValue)
				schema := asMap(media["schema"])
				if schema["type"] == "object" || schema["type"] == "array" {
					key := componentCandidateKey{context: "Response", fingerprint: schemaFingerprint(schema)}
					candidates[key] = append(candidates[key], componentUse{path: op.path, method: op.method, key: status + ":" + ct, schema: schema})
				}
			}
		}
	}

	components := asMap(doc["components"])
	schemas := asMap(components["schemas"])
	usedNames := map[string]struct{}{}
	for name := range schemas {
		usedNames[name] = struct{}{}
	}
	refs := map[componentCandidateKey]string{}
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
	for _, key := range keys {
		uses := candidates[key]
		if len(uses) < 2 {
			continue
		}
		name := uniqueComponentName(componentBaseName(uses[0].path, key.context), usedNames)
		schemas[name] = uses[0].schema
		refs[key] = "#/components/schemas/" + name
	}
	if len(refs) == 0 {
		if len(schemas) > 0 {
			components["schemas"] = schemas
			doc["components"] = components
		}
		return
	}
	components["schemas"] = schemas
	doc["components"] = components

	for _, op := range operations {
		opDict := asMap(asMap(asMap(doc["paths"])[op.path])[op.method])
		requestBody := asMap(opDict["requestBody"])
		for _, mediaValue := range asMap(requestBody["content"]) {
			media := asMap(mediaValue)
			schema := asMap(media["schema"])
			ref := refs[componentCandidateKey{context: "Request", fingerprint: schemaFingerprint(schema)}]
			if ref != "" {
				media["schema"] = map[string]any{"$ref": ref}
			}
		}
		for _, responseValue := range asMap(opDict["responses"]) {
			response := asMap(responseValue)
			for _, mediaValue := range asMap(response["content"]) {
				media := asMap(mediaValue)
				schema := asMap(media["schema"])
				ref := refs[componentCandidateKey{context: "Response", fingerprint: schemaFingerprint(schema)}]
				if ref != "" {
					media["schema"] = map[string]any{"$ref": ref}
				}
			}
		}
	}
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

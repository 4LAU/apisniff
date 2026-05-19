package spec

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/4LAU/apisniff-go/internal/auth"
	"github.com/4LAU/apisniff-go/internal/model"
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

func IsAPIFlow(flow model.CapturedFlow) bool {
	if strings.Contains(flow.ContentType(), "json") {
		return true
	}
	reqCT := contentTypeBase(model.GetHeader(flow.RequestHeaders, "content-type"))
	_, ok := apiContentTypes[reqCT]
	return ok
}

func Generate(flows []model.CapturedFlow, domain string, patterns []auth.Pattern, opts Options) map[string]any {
	type groupKey struct {
		path   string
		method string
	}
	groups := map[groupKey][]model.CapturedFlow{}
	for _, flow := range flows {
		key := groupKey{path: model.NormalizePath(flow.Path), method: strings.ToLower(flow.Method)}
		groups[key] = append(groups[key], flow)
	}

	paths := map[string]any{}
	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path == keys[j].path {
			return keys[i].method < keys[j].method
		}
		return keys[i].path < keys[j].path
	})

	for _, key := range keys {
		operation := map[string]any{"responses": map[string]any{}}
		addQueryParameters(operation, groups[key])
		addResponses(operation, groups[key], opts)
		addRequestBody(operation, key.method, groups[key], opts)

		pathItem := asMap(paths[key.path])
		pathItem[key.method] = operation
		paths[key.path] = pathItem
	}

	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       domain + " API",
			"version":     "0.1.0",
			"description": "Auto-generated from captured traffic for " + domain,
		},
		"servers": []any{map[string]any{"url": "https://" + domain}},
		"paths":   paths,
	}
	addAuth(doc, patterns, opts.InferSchemes)
	return doc
}

func addQueryParameters(operation map[string]any, flows []model.CapturedFlow) {
	seen := map[string]map[string]any{}
	for _, flow := range flows {
		_, rawQuery, ok := strings.Cut(flow.Path, "?")
		if !ok {
			continue
		}
		values, _ := url.ParseQuery(rawQuery)
		for name := range values {
			if _, ok := seen[name]; !ok {
				seen[name] = map[string]any{"name": name, "in": "query", "schema": map[string]any{"type": "string"}}
			}
		}
	}
	if len(seen) == 0 {
		return
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	params := make([]any, 0, len(names))
	for _, name := range names {
		params = append(params, seen[name])
	}
	operation["parameters"] = params
}

func addResponses(operation map[string]any, flows []model.CapturedFlow, opts Options) {
	responses := asMap(operation["responses"])
	responseSchemas := map[string]map[string]any{}
	for _, flow := range flows {
		statusKey := json.Number(string(rune(0)))
		_ = statusKey
		key := intString(flow.ResponseStatus)
		if _, ok := responses[key]; !ok {
			responses[key] = map[string]any{"description": "Observed response"}
		}
		if parsed := ParseJSONBody(flow.ResponseBody); parsed != nil {
			schema := InferSchema(parsed, opts.IncludeExamples, "")
			if existing, ok := responseSchemas[key]; ok {
				responseSchemas[key] = MergeSchemas(existing, schema)
			} else {
				responseSchemas[key] = schema
			}
		}
	}
	for key, schema := range responseSchemas {
		response := asMap(responses[key])
		response["content"] = map[string]any{"application/json": map[string]any{"schema": schema}}
		responses[key] = response
	}
	operation["responses"] = responses
}

func addRequestBody(operation map[string]any, method string, flows []model.CapturedFlow, opts Options) {
	if method != "post" && method != "put" && method != "patch" {
		return
	}
	content := map[string]any{}
	for _, flow := range flows {
		if len(flow.RequestBody) == 0 {
			continue
		}
		rawCT := model.GetHeader(flow.RequestHeaders, "content-type")
		ct := contentTypeBase(rawCT)
		switch ct {
		case "application/json":
			if parsed := ParseJSONBody(flow.RequestBody); parsed != nil {
				upsertContentSchema(content, ct, InferSchema(parsed, opts.IncludeExamples, ""))
			}
		case "application/x-www-form-urlencoded":
			if parsed := ParseFormURLEncoded(flow.RequestBody); parsed != nil {
				upsertContentSchema(content, ct, InferSchema(parsed, opts.IncludeExamples, ""))
			}
		case "multipart/form-data":
			if parsed := ParseMultipart(flow.RequestBody, rawCT); parsed != nil {
				props := map[string]any{}
				for key, value := range parsed {
					if value == fileSentinel {
						props[key] = map[string]any{"type": "string", "format": "binary"}
					} else {
						props[key] = InferSchema(value, opts.IncludeExamples, key)
					}
				}
				upsertContentSchema(content, ct, map[string]any{"type": "object", "properties": props})
			}
		}
	}
	if len(content) > 0 {
		operation["requestBody"] = map[string]any{"content": content}
	}
}

func upsertContentSchema(content map[string]any, ct string, schema map[string]any) {
	if existing, ok := content[ct]; ok {
		entry := asMap(existing)
		entry["schema"] = MergeSchemas(asMap(entry["schema"]), schema)
		content[ct] = entry
		return
	}
	content[ct] = map[string]any{"schema": schema}
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
		if IsAPIFlow(flow) || hasCategoryTag(flow, "business_api") || hasCategoryTag(flow, "auth") || hasCategoryTag(flow, "antibot") {
			out = append(out, flow)
		}
	}
	return out
}

func hasCategoryTag(flow model.CapturedFlow, category string) bool {
	for _, tag := range flow.Tags {
		if tag == "category:"+category {
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

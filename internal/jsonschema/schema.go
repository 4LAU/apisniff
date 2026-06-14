package jsonschema

import (
	"encoding/json"
	"regexp"
	"sort"
)

const maxExampleLen = 200

// FileSentinel marks a multipart form field whose value is an uploaded file
// rather than an inferable JSON value.
const FileSentinel = "__file__"
const maxSchemaDepth = 20

var secretRe = regexp.MustCompile(`(?i)(bearer |basic |eyj[A-Za-z0-9_-]{10,}|sk_|pk_|api_|ghp_|gho_|ghs_|glpat-|xox[bpsar]-|AKIA[0-9A-Z]{16}|wJalrX|-----BEGIN)`)
var sensitiveFieldRe = regexp.MustCompile(`(?i)(password|passwd|(^|[_-])secret([_-]|$)|credential|api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|\bauth\b|authorization|auth[_-]|(^|[_-])token([_-]|$)|ssn|social[_-]?security|x-api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)`)
var mapKeyRe = regexp.MustCompile(`(?i)^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

func InferSchema(value any, includeExamples bool, fieldName string) map[string]any {
	return inferSchemaRecursive(value, includeExamples, fieldName, maxSchemaDepth)
}

func inferSchemaRecursive(value any, includeExamples bool, fieldName string, depth int) map[string]any {
	if depth <= 0 {
		return map[string]any{"type": "object"}
	}
	if value == nil {
		return map[string]any{"type": "string", "nullable": true}
	}
	sensitive := fieldName != "" && sensitiveFieldRe.MatchString(fieldName)
	switch typed := value.(type) {
	case bool:
		schema := map[string]any{"type": "boolean"}
		addExample(schema, typed, includeExamples, sensitive)
		return schema
	case int:
		schema := map[string]any{"type": "integer"}
		addExample(schema, typed, includeExamples, sensitive)
		return schema
	case int64:
		schema := map[string]any{"type": "integer"}
		addExample(schema, typed, includeExamples, sensitive)
		return schema
	case float64:
		if float64(int64(typed)) == typed {
			schema := map[string]any{"type": "integer"}
			addExample(schema, int64(typed), includeExamples, sensitive)
			return schema
		}
		schema := map[string]any{"type": "number"}
		addExample(schema, typed, includeExamples, sensitive)
		return schema
	case string:
		schema := map[string]any{"type": "string"}
		if includeExamples {
			example := redactIfSecret(typed)
			if sensitive {
				example = "***REDACTED***"
			}
			if len(example) > maxExampleLen {
				example = example[:maxExampleLen] + "..."
			}
			schema["example"] = example
		}
		return schema
	case []any:
		if len(typed) == 0 {
			return map[string]any{"type": "array", "items": map[string]any{}}
		}
		merged := map[string]any{}
		for _, item := range typed {
			merged = MergeSchemas(merged, inferSchemaRecursive(item, includeExamples, fieldName, depth-1))
		}
		return map[string]any{"type": "array", "items": merged}
	case map[string]any:
		if len(typed) > 0 && allMapKeys(typed) {
			additional := map[string]any{}
			for _, child := range typed {
				additional = MergeSchemas(additional, inferSchemaRecursive(child, includeExamples, fieldName, depth-1))
			}
			if len(additional) == 0 {
				return map[string]any{"type": "object", "additionalProperties": true}
			}
			return map[string]any{"type": "object", "additionalProperties": additional}
		}
		props := map[string]any{}
		for key, child := range typed {
			props[key] = inferSchemaRecursive(child, includeExamples, key, depth-1)
		}
		return map[string]any{"type": "object", "properties": props}
	default:
		schema := map[string]any{"type": "string"}
		addExample(schema, typed, includeExamples, sensitive)
		return schema
	}
}

func ParseJSONBody(body []byte) any {
	if len(body) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil
	}
	return value
}

func MergeSchemas(existing, new map[string]any) map[string]any {
	if len(existing) == 0 {
		return new
	}
	if len(new) == 0 {
		return existing
	}
	existingType, _ := existing["type"].(string)
	newType, _ := new["type"].(string)
	if existingType != newType {
		eitherNullable := truthy(existing["nullable"]) || truthy(new["nullable"])
		if isNullSentinel(existing) {
			result := copyMap(new)
			result["nullable"] = true
			return result
		}
		if isNullSentinel(new) {
			result := copyMap(existing)
			result["nullable"] = true
			return result
		}
		if (newType == "object" || newType == "array") && existingType != "object" && existingType != "array" {
			result := copyMap(new)
			if eitherNullable && !truthy(result["nullable"]) {
				result["nullable"] = true
			}
			return result
		}
		if (existingType == "object" || existingType == "array") && newType != "object" && newType != "array" {
			result := copyMap(existing)
			if eitherNullable && !truthy(result["nullable"]) {
				result["nullable"] = true
			}
			return result
		}
		if (existingType == "integer" && newType == "number") || (existingType == "number" && newType == "integer") {
			result := map[string]any{"type": "number"}
			if eitherNullable {
				result["nullable"] = true
			}
			if example, ok := mergeExample(existing, new); ok {
				result["example"] = example
			}
			return result
		}
		result := map[string]any{"type": "string"}
		if eitherNullable {
			result["nullable"] = true
		}
		if observed := observedTypes(existing, new); len(observed) > 0 {
			result["x-apisniff-observed-types"] = observed
		}
		return result
	}
	switch existingType {
	case "object":
		result := copyMap(existing)
		if truthy(existing["nullable"]) || truthy(new["nullable"]) {
			result["nullable"] = true
		}
		if _, ok := existing["additionalProperties"]; ok || new["additionalProperties"] != nil {
			result["additionalProperties"] = mergeAdditionalProperties(existing["additionalProperties"], new["additionalProperties"])
			delete(result, "properties")
			return result
		}
		mergedProps := copyMap(asMap(existing["properties"]))
		newProps := asMap(new["properties"])
		for key, value := range newProps {
			if current, ok := mergedProps[key]; ok {
				mergedProps[key] = MergeSchemas(asMap(current), asMap(value))
			} else {
				mergedProps[key] = value
			}
		}
		result["properties"] = mergedProps
		return result
	case "array":
		existingItems := asMap(existing["items"])
		newItems := asMap(new["items"])
		result := copyMap(existing)
		if truthy(existing["nullable"]) || truthy(new["nullable"]) {
			result["nullable"] = true
		}
		switch {
		case len(existingItems) == 0 && len(newItems) > 0:
			result["items"] = newItems
		case len(existingItems) > 0 && len(newItems) > 0:
			result["items"] = MergeSchemas(existingItems, newItems)
		}
		return result
	default:
		result := copyMap(existing)
		if truthy(existing["nullable"]) || truthy(new["nullable"]) {
			result["nullable"] = true
		}
		if example, ok := mergeExample(existing, new); ok {
			result["example"] = example
		}
		if observed := observedTypes(existing, new); len(observed) > 1 {
			result["x-apisniff-observed-types"] = observed
		}
		return result
	}
}

func isNullSentinel(schema map[string]any) bool {
	return schema["type"] == "string" && truthy(schema["nullable"]) && len(schema) == 2
}

func allMapKeys(value map[string]any) bool {
	for key := range value {
		if !mapKeyRe.MatchString(key) {
			return false
		}
	}
	return true
}

func truthy(value any) bool {
	typed, _ := value.(bool)
	return typed
}

func observedTypes(schemas ...map[string]any) []any {
	seen := map[string]struct{}{}
	for _, schema := range schemas {
		if schemaType, ok := schema["type"].(string); ok && schemaType != "" {
			seen[schemaType] = struct{}{}
		}
		for _, value := range toAnySlice(schema["x-apisniff-observed-types"]) {
			if str, ok := value.(string); ok && str != "" {
				seen[str] = struct{}{}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, key)
	}
	return out
}

func toAnySlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []string:
		out := make([]any, 0, len(typed))
		for _, value := range typed {
			out = append(out, value)
		}
		return out
	default:
		return nil
	}
}

func mergeAdditionalProperties(existing, new any) any {
	if existing == true || new == true {
		if existingMap, ok := existing.(map[string]any); ok {
			return existingMap
		}
		if newMap, ok := new.(map[string]any); ok {
			return newMap
		}
		return true
	}
	existingMap, existingOK := existing.(map[string]any)
	newMap, newOK := new.(map[string]any)
	switch {
	case existingOK && newOK:
		return MergeSchemas(existingMap, newMap)
	case existingOK:
		return existingMap
	case newOK:
		return newMap
	default:
		return true
	}
}

func mergeExample(existing, new map[string]any) (any, bool) {
	existingExample, existingOK := existing["example"]
	newExample, newOK := new["example"]
	switch {
	case existingOK && newOK:
		if exampleSortKey(existingExample) <= exampleSortKey(newExample) {
			return existingExample, true
		}
		return newExample, true
	case existingOK:
		return existingExample, true
	case newOK:
		return newExample, true
	default:
		return nil, false
	}
}

func exampleSortKey(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func addExample(schema map[string]any, value any, include bool, sensitive bool) {
	if !include {
		return
	}
	if sensitive {
		schema["example"] = "***REDACTED***"
		return
	}
	if str, ok := value.(string); ok {
		schema["example"] = redactIfSecret(str)
		return
	}
	schema["example"] = value
}

func redactIfSecret(value string) string {
	if secretRe.MatchString(value) {
		return "***REDACTED***"
	}
	return value
}

func asMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

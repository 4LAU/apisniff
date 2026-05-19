package spec

import (
	"encoding/json"
	"regexp"
	"strings"
)

const maxExampleLen = 200
const fileSentinel = "__file__"

var secretRe = regexp.MustCompile(`(?i)(bearer |basic |eyj|sk_|pk_|api_|ghp_|gho_|ghs_|glpat-|xox[bpsar]-|AKIA)`)
var sensitiveFieldRe = regexp.MustCompile(`(?i)(password|passwd|(^|_)secret(_|$)|credential|api_?key|private_?key|access_?token|refresh_?token|client_?secret|\bauth\b|auth_|(^|_)token(_|$)|ssn|social_?security)`)

func InferSchema(value any, includeExamples bool, fieldName string) map[string]any {
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
		return map[string]any{"type": "array", "items": InferSchema(typed[0], includeExamples, fieldName)}
	case map[string]any:
		props := map[string]any{}
		for key, child := range typed {
			props[key] = InferSchema(child, includeExamples, key)
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
		if (newType == "object" || newType == "array") && existingType != "object" && existingType != "array" {
			return new
		}
		return existing
	}
	switch existingType {
	case "object":
		mergedProps := copyMap(asMap(existing["properties"]))
		for key, value := range asMap(new["properties"]) {
			if current, ok := mergedProps[key]; ok {
				mergedProps[key] = MergeSchemas(asMap(current), asMap(value))
			} else {
				mergedProps[key] = value
			}
		}
		result := copyMap(existing)
		result["properties"] = mergedProps
		return result
	case "array":
		existingItems := asMap(existing["items"])
		newItems := asMap(new["items"])
		result := copyMap(existing)
		switch {
		case len(existingItems) == 0 && len(newItems) > 0:
			result["items"] = newItems
		case len(existingItems) > 0 && len(newItems) > 0:
			result["items"] = MergeSchemas(existingItems, newItems)
		}
		return result
	default:
		return existing
	}
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

func isSensitiveField(name string) bool {
	return sensitiveFieldRe.MatchString(strings.ToLower(name))
}

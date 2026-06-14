package spec

// asMap returns value as a map[string]any, or an empty map when value is nil or
// not a map. A private copy lives here (mirroring jsonschema.asMap) so the spec
// package does not depend on jsonschema for this trivial helper.
func asMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

// toAnySlice normalizes value to []any, returning nil for unsupported types. A
// private copy lives here (mirroring jsonschema.toAnySlice) so the spec package
// does not depend on jsonschema for this trivial helper.
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

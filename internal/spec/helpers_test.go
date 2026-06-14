package spec

// toAnySlice normalizes value to []any, returning nil for unsupported types.
// This is a test-only helper used by the spec package tests to inspect generated
// document slices; it has no production callers.
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

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

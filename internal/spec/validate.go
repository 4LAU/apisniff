package spec

import (
	"context"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
)

func Validate(doc map[string]any, format string) error {
	data, err := Marshal(doc, format)
	if err != nil {
		return fmt.Errorf("marshal for validation: %w", err)
	}
	loader := openapi3.NewLoader()
	loaded, err := loader.LoadFromData(data)
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	if err := loaded.Validate(context.Background()); err != nil {
		return fmt.Errorf("invalid OpenAPI spec: %w", err)
	}
	return nil
}

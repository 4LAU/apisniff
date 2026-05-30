package spec

import (
	"context"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
)

func MarshalAndValidate(doc map[string]any, format string) ([]byte, error) {
	data, err := Marshal(doc, format)
	if err != nil {
		return nil, fmt.Errorf("marshal spec: %w", err)
	}
	if err := ValidateBytes(data); err != nil {
		return nil, err
	}
	return data, nil
}

func ValidateBytes(data []byte) error {
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

package spec

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/testutil"
	"github.com/getkin/kin-openapi/openapi3"
)

var fixtureCases = []struct {
	name   string
	domain string
}{
	{"minimal.har", "example.com"},
	{"minimal.burp.xml", "example.com"},
	{"minimal.jsonl", "example.com"},
	{"multisite.har", "example.com"},
	{"auth_variants.har", "example.com"},
	{"redaction.jsonl", "example.com"},
	{"complex.jsonl", "example.com"},
}

func loadFixtureSpec(t *testing.T, fixtureName string, domain string, opts Options) map[string]any {
	t.Helper()
	flows, _, err := adapter.LoadFlows(filepath.Join(testutil.RepoRoot(t), "testdata", "fixtures", fixtureName))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) == 0 {
		t.Fatalf("fixture %s produced no flows", fixtureName)
	}
	return Generate(flows, domain, nil, opts)
}

func TestGeneratedSpecsPassStructuralValidation(t *testing.T) {
	for _, tc := range fixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := loadFixtureSpec(t, tc.name, tc.domain, Options{})
			data, err := Marshal(doc, "json")
			if err != nil {
				t.Fatal(err)
			}
			loader := openapi3.NewLoader()
			loaded, err := loader.LoadFromData(data)
			if err != nil {
				t.Fatal(err)
			}
			if err := loaded.Validate(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPathParamsDeclared(t *testing.T) {
	pathParamRe := regexp.MustCompile(`\{(\w+)\}`)
	for _, tc := range fixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := loadFixtureSpec(t, tc.name, tc.domain, Options{})
			for path, methodsValue := range asMap(doc["paths"]) {
				matches := pathParamRe.FindAllStringSubmatch(path, -1)
				if len(matches) == 0 {
					continue
				}
				expected := map[string]struct{}{}
				for _, match := range matches {
					expected[match[1]] = struct{}{}
				}
				for method, operationValue := range asMap(methodsValue) {
					declared := map[string]struct{}{}
					for _, paramValue := range toAnySlice(asMap(operationValue)["parameters"]) {
						param := asMap(paramValue)
						if param["in"] == "path" {
							declared[param["name"].(string)] = struct{}{}
						}
					}
					for name := range expected {
						if _, ok := declared[name]; !ok {
							t.Fatalf("%s.%s missing path parameter %s", path, method, name)
						}
					}
				}
			}
		})
	}
}

func TestSpecOutputDeterministic(t *testing.T) {
	for _, tc := range fixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			first := loadFixtureSpec(t, tc.name, tc.domain, Options{})
			second := loadFixtureSpec(t, tc.name, tc.domain, Options{})
			firstJSON, err := Marshal(first, "json")
			if err != nil {
				t.Fatal(err)
			}
			secondJSON, err := Marshal(second, "json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstJSON, secondJSON) {
				t.Fatal("Generate produced non-deterministic JSON")
			}
		})
	}
}

func TestSerializedPathKeysSorted(t *testing.T) {
	for _, tc := range fixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := loadFixtureSpec(t, tc.name, tc.domain, Options{})
			data, err := Marshal(doc, "json")
			if err != nil {
				t.Fatal(err)
			}
			paths := asMap(doc["paths"])
			keys := make([]string, 0, len(paths))
			for path := range paths {
				keys = append(keys, path)
			}
			sort.Strings(keys)
			previousIndex := -1
			for _, path := range keys {
				encoded, err := json.Marshal(path)
				if err != nil {
					t.Fatal(err)
				}
				needle := "\n    " + string(encoded) + ":"
				index := strings.Index(string(data), needle)
				if index < 0 {
					t.Fatalf("serialized path key %s not found", path)
				}
				if index <= previousIndex {
					t.Fatalf("serialized path key %s is out of order", path)
				}
				previousIndex = index
			}
		})
	}
}

func TestNoExamplesByDefault(t *testing.T) {
	for _, tc := range fixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := loadFixtureSpec(t, tc.name, tc.domain, Options{})
			data, err := Marshal(doc, "json")
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(`"example":`)) {
				t.Fatal("spec contains examples with IncludeExamples=false")
			}
		})
	}
}

func TestRoundTripResponseSchemasMatchTraffic(t *testing.T) {
	for _, tc := range fixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			repoRoot := testutil.RepoRoot(t)
			flows, _, err := adapter.LoadFlows(filepath.Join(repoRoot, "testdata", "fixtures", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			apiFlows := FilterAPIFlows(flows)
			doc := Generate(apiFlows, tc.domain, nil, Options{})

			data, err := Marshal(doc, "json")
			if err != nil {
				t.Fatal(err)
			}
			loader := openapi3.NewLoader()
			loaded, err := loader.LoadFromData(data)
			if err != nil {
				t.Fatal(err)
			}

			for _, flow := range apiFlows {
				if len(flow.ResponseBody) == 0 {
					continue
				}
				parsed := ParseJSONBody(flow.ResponseBody)
				if parsed == nil {
					continue
				}
				normalizedPath := model.NormalizePath(flow.Path)
				pathItem := loaded.Paths.Find(normalizedPath)
				if pathItem == nil {
					continue
				}
				method := strings.ToLower(flow.Method)
				op := pathItem.GetOperation(strings.ToUpper(method))
				if op == nil {
					continue
				}
				status := strconv.Itoa(flow.ResponseStatus)
				resp := op.Responses.Status(flow.ResponseStatus)
				if resp == nil {
					continue
				}
				ct := flow.ContentType()
				if ct == "" {
					ct = "application/json"
				}
				mediaType := resp.Value.Content.Get(ct)
				if mediaType == nil || mediaType.Schema == nil {
					continue
				}
				schema := mediaType.Schema.Value
				if schema == nil {
					continue
				}
				assertSchemaCovers(t, tc.name, method+" "+normalizedPath+" "+status, schema, parsed)
			}
		})
	}
}

func assertSchemaCovers(t *testing.T, fixture, label string, schema *openapi3.Schema, value any) {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		if schema.Type != nil && !schema.Type.Includes("object") {
			t.Errorf("%s [%s]: expected object schema, got %v", fixture, label, schema.Type)
			return
		}
		for key, child := range v {
			if child == nil {
				continue
			}
			propRef := schema.Properties[key]
			if propRef == nil || propRef.Value == nil {
				continue
			}
			assertSchemaCovers(t, fixture, label+"."+key, propRef.Value, child)
		}
	case []any:
		if schema.Type != nil && !schema.Type.Includes("array") {
			t.Errorf("%s [%s]: expected array schema, got %v", fixture, label, schema.Type)
			return
		}
		if schema.Items != nil && schema.Items.Value != nil && len(v) > 0 {
			assertSchemaCovers(t, fixture, label+"[0]", schema.Items.Value, v[0])
		}
	case float64:
		if schema.Type != nil && !schema.Type.Includes("integer") && !schema.Type.Includes("number") && !schema.Type.Includes("string") {
			t.Errorf("%s [%s]: numeric value but schema type is %v", fixture, label, schema.Type)
		}
	case string:
		if schema.Type != nil && !schema.Type.Includes("string") {
			t.Errorf("%s [%s]: string value but schema type is %v", fixture, label, schema.Type)
		}
	case bool:
		if schema.Type != nil && !schema.Type.Includes("boolean") && !schema.Type.Includes("string") {
			t.Errorf("%s [%s]: boolean value but schema type is %v", fixture, label, schema.Type)
		}
	}
}

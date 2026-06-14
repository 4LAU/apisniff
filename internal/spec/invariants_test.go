package spec

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/jsonschema"
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

func FuzzAdapterBoundaryGenerateMarshalValidate(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"method":"GET","host":"example.com","path":"/api/fuzz","url":"https://example.com/api/fuzz","response_status":200,"response_headers":{"content-type":"application/json"},"response_body":"eyJvayI6dHJ1ZX0=","_body_encoding":"base64"}` + "\n"),
		[]byte(`{"method":"CONNECT","host":"example.com","path":"/api/tunnel","url":"https://example.com/api/tunnel","response_status":200,"response_headers":{"content-type":"application/json"},"response_body":"eyJvayI6dHJ1ZX0=","_body_encoding":"base64"}` + "\n"),
		[]byte(`{"method":"GET","path":"/api/bad","response_status":0}` + "\n"),
		[]byte(`not jsonl`),
		[]byte{},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "flows.jsonl")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}

		flows, _, err := adapter.LoadFlows(path)
		if err != nil {
			return
		}
		doc, err := Generate(FilterAPIFlows(flows), "example.com", nil, Options{})
		if errors.Is(err, ErrNoValidAPIFlows) {
			return
		}
		if err != nil {
			t.Fatalf("Generate returned unexpected error: %v", err)
		}
		if _, err := MarshalAndValidate(doc, "json"); err != nil {
			t.Fatalf("generated spec did not validate: %v", err)
		}
	})
}

func TestSpecEdgeCaseFixturePassesGenerationInvariants(t *testing.T) {
	flows, _, err := adapter.LoadFlows(filepath.Join(testutil.RepoRoot(t), "testdata", "fixtures", "spec_edge_cases.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Generate(FilterAPIFlows(flows), "https://{Example}.com/api", nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalAndValidate(doc, "json"); err != nil {
		t.Fatal(err)
	}

	servers := toAnySlice(doc["servers"])
	if len(servers) != 1 || asMap(servers[0])["url"] != "https://example.com" {
		t.Fatalf("servers = %#v", servers)
	}

	paths := asMap(doc["paths"])
	for _, path := range []string{
		"/api/status/zero",
		"/api/status/out-of-range",
		"/api/empty-method",
		"/api/connect",
		"/api/{broken",
	} {
		if paths[path] != nil {
			t.Fatalf("invalid fixture path %s survived into spec paths: %#v", path, paths[path])
		}
	}
	if paths["/api/resources/{resourceId}"] == nil || paths["/api/search"] == nil || paths["/api/deep"] == nil {
		t.Fatalf("expected edge-case paths missing: %#v", paths)
	}

	params := toAnySlice(operation(doc, "/api/search", "get")["parameters"])
	for _, paramValue := range params {
		param := asMap(paramValue)
		if param["name"] == "" {
			t.Fatalf("blank query parameter survived: %#v", params)
		}
	}

	if paths["/api/mixed"] == nil || paths["/api/text-jsonlike"] == nil {
		t.Fatalf("expected edge-case paths /api/mixed and /api/text-jsonlike missing: %#v", paths)
	}

	mixedContent := asMap(asMap(asMap(operation(doc, "/api/mixed", "get")["responses"])["200"])["content"])
	if mixedContent["application/json"] == nil || mixedContent["application/problem+json"] == nil {
		t.Fatalf("mixed JSON content types missing: %#v", mixedContent)
	}
	textResponse := asMap(asMap(operation(doc, "/api/text-jsonlike", "get")["responses"])["200"])
	if asMap(textResponse["content"])["text/plain"] != nil {
		t.Fatalf("non-JSON response body was treated as JSON content: %#v", textResponse)
	}
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
	return mustGenerate(t, flows, domain, nil, opts)
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
			doc := mustGenerate(t, apiFlows, tc.domain, nil, Options{})

			data, err := Marshal(doc, "json")
			if err != nil {
				t.Fatal(err)
			}
			loader := openapi3.NewLoader()
			loaded, err := loader.LoadFromData(data)
			if err != nil {
				t.Fatal(err)
			}

			checked := 0
			for _, flow := range apiFlows {
				if len(flow.ResponseBody) == 0 {
					continue
				}
				parsed := jsonschema.ParseJSONBody(flow.ResponseBody)
				if parsed == nil {
					continue
				}
				normalizedPath := model.NormalizePath(flow.Path)
				method := strings.ToLower(flow.Method)
				label := method + " " + normalizedPath + " " + strconv.Itoa(flow.ResponseStatus)

				pathItem := loaded.Paths.Find(normalizedPath)
				if pathItem == nil {
					t.Errorf("%s: path %s not found in spec", tc.name, normalizedPath)
					continue
				}
				op := pathItem.GetOperation(strings.ToUpper(method))
				if op == nil {
					t.Errorf("%s: operation %s not found for %s", tc.name, strings.ToUpper(method), normalizedPath)
					continue
				}
				resp := op.Responses.Status(flow.ResponseStatus)
				if resp == nil {
					t.Errorf("%s: response %d not found for %s", tc.name, flow.ResponseStatus, label)
					continue
				}
				ct := flow.ContentType()
				if ct == "" {
					ct = "application/json"
				}
				mediaType := resp.Value.Content.Get(ct)
				if mediaType == nil {
					t.Errorf("%s: media type %s not found for %s", tc.name, ct, label)
					continue
				}
				if mediaType.Schema == nil || mediaType.Schema.Value == nil {
					t.Errorf("%s: schema missing for %s", tc.name, label)
					continue
				}
				schema := mediaType.Schema.Value
				checked++
				assertSchemaCovers(t, tc.name, label, schema, parsed)
			}
			if checked == 0 {
				t.Fatal("round-trip test checked zero flows — test is not exercising anything")
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
				hasAdditional := schema.AdditionalProperties.Schema != nil || (schema.AdditionalProperties.Has != nil && *schema.AdditionalProperties.Has)
				if !hasAdditional {
					t.Errorf("%s [%s]: property %q in traffic but not in schema", fixture, label, key)
				}
				continue
			}
			assertSchemaCovers(t, fixture, label+"."+key, propRef.Value, child)
		}
	case []any:
		if schema.Type != nil && !schema.Type.Includes("array") {
			t.Errorf("%s [%s]: expected array schema, got %v", fixture, label, schema.Type)
			return
		}
		if len(v) > 0 && (schema.Items == nil || schema.Items.Value == nil) {
			t.Errorf("%s [%s]: non-empty array but no items schema", fixture, label)
			return
		}
		if schema.Items != nil && schema.Items.Value != nil {
			for i, item := range v {
				assertSchemaCovers(t, fixture, label+"["+strconv.Itoa(i)+"]", schema.Items.Value, item)
			}
		}
	case float64:
		isInt := v == math.Trunc(v)
		if schema.Type != nil {
			if isInt {
				if !schema.Type.Includes("integer") && !schema.Type.Includes("number") {
					t.Errorf("%s [%s]: integer value but schema type is %v", fixture, label, schema.Type)
				}
			} else {
				if !schema.Type.Includes("number") {
					t.Errorf("%s [%s]: non-integer numeric value but schema type is %v", fixture, label, schema.Type)
				}
			}
		}
	case string:
		if schema.Type != nil && !schema.Type.Includes("string") {
			t.Errorf("%s [%s]: string value but schema type is %v", fixture, label, schema.Type)
		}
	case bool:
		if schema.Type != nil && !schema.Type.Includes("boolean") {
			t.Errorf("%s [%s]: boolean value but schema type is %v", fixture, label, schema.Type)
		}
	}
}

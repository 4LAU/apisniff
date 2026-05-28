package spec

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/adapter"
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

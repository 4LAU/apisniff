package spec

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/testutil"
)

var updateGoldens = flag.Bool("update", false, "update golden spec fixtures")

func TestGoldenSpecParity(t *testing.T) {
	for _, tc := range fixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			repoRoot := testutil.RepoRoot(t)
			flows, _, err := adapter.LoadFlows(filepath.Join(repoRoot, "testdata", "fixtures", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			got := Generate(flows, tc.domain, nil, Options{})
			goldenPath := filepath.Join(repoRoot, "testdata", "golden", "spec", tc.name+".json")
			if *updateGoldens {
				data, err := json.MarshalIndent(got, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, '\n')
				if err := os.WriteFile(goldenPath, data, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			data, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if err := json.Unmarshal(data, &want); err != nil {
				t.Fatal(err)
			}
			gotData, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var gotNormalized any
			if err := json.Unmarshal(gotData, &gotNormalized); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotNormalized, want) {
				gotPretty, _ := json.MarshalIndent(gotNormalized, "", "  ")
				wantPretty, _ := json.MarshalIndent(want, "", "  ")
				t.Fatalf("spec does not match golden\nwant:\n%s\n\ngot:\n%s", wantPretty, gotPretty)
			}
		})
	}
}

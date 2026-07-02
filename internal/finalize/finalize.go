// Package finalize co-locates the OpenAPI spec and the PRIVATE GraphQL catalog
// inside a capture-bundle directory so every capture path and offline analyze
// produce the same artifacts from the same shared pipeline.
package finalize

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/graphql"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/spec"
)

// Summary reports the catalog counts produced by FinalizeBundle, for terminal
// reporting. All counts are zero when no GraphQL operations were observed.
type Summary struct {
	OperationCount     int
	FlowCount          int
	CapturedQueryCount int
	PersistedHashCount int
}

// FinalizeBundle writes the OpenAPI spec and the PRIVATE GraphQL catalog into dir using
// the in-memory flows. dir MUST be a private (0o600) capture-bundle directory —
// the catalog contains raw URLs and raw variable values (credentials/PII) and is
// never shareable. Safe to call with no GraphQL ops (catalog is cleared).
func FinalizeBundle(dir string, flows []model.CapturedFlow, domain string) (Summary, error) {
	pipeline, err := spec.BuildPipeline(flows, domain, spec.InclusionOptions{})
	if err != nil {
		return Summary{}, err
	}
	if err := writeSpec(dir, pipeline, domain); err != nil {
		return Summary{}, err
	}
	cat := graphql.BuildCatalog(pipeline.APIFlows)
	if err := graphql.WriteCatalog(dir, cat); err != nil {
		return Summary{}, err
	}
	return summarize(cat), nil
}

// FromBundle reloads the captured flows from flowsPath and finalizes the bundle
// (writes the OpenAPI spec + the private GraphQL catalog into bundleDir). It is non-fatal:
// the capture already succeeded, so any error is written to warnW (nil discards)
// and an empty Summary returned rather than propagated. bundleDir must be a
// private capture-bundle dir.
func FromBundle(warnW io.Writer, bundleDir, flowsPath, domain string) Summary {
	if warnW == nil {
		warnW = io.Discard
	}
	flows, err := adapter.LoadJSONL(flowsPath)
	if err != nil {
		fmt.Fprintf(warnW, "WARNING: could not reload captured flows from %s (%v); %s and the GraphQL catalog were not written.\n",
			flowsPath, err, spec.OpenAPIFileName)
		return Summary{}
	}
	sum, err := FinalizeBundle(bundleDir, flows, domain)
	if err != nil {
		fmt.Fprintf(warnW, "WARNING: could not finalize %s (%v); %s and the GraphQL catalog may be missing or incomplete.\n",
			bundleDir, err, spec.OpenAPIFileName)
		return Summary{}
	}
	return sum
}

// writeSpec generates and writes the OpenAPI spec at mode 0o600, skipping the write
// (no error) when the pipeline yields no API flows worth a spec.
func writeSpec(dir string, pipeline spec.PipelineResult, domain string) error {
	specDoc, err := spec.Generate(pipeline.APIFlows, domain, pipeline.Auth,
		spec.Options{InferSchemes: true, IncludeExamples: true})
	if errors.Is(err, spec.ErrNoValidAPIFlows) {
		return nil
	}
	if err != nil {
		return err
	}
	// Bundle spec is an internal artifact — skip strict validation so one
	// invalid example field doesn't block the entire spec from being written.
	data, err := spec.Marshal(specDoc, "yaml")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, spec.OpenAPIFileName), data, 0o600)
}

// summarize derives the Summary from a built catalog, splitting operations by
// source.
func summarize(cat graphql.Catalog) Summary {
	sum := Summary{OperationCount: cat.OperationCount, FlowCount: cat.FlowCount}
	for _, op := range cat.Operations {
		switch op.Source {
		case "captured-query":
			sum.CapturedQueryCount++
		case "persisted-hash":
			sum.PersistedHashCount++
		}
	}
	return sum
}

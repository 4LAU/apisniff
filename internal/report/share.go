package report

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/bundle"
	"github.com/4LAU/apisniff/internal/spec"
)

type ShareOptions struct {
	BundleOrDomain string
	OutputDir      string
	Domain         string
}

type ShareResult struct {
	OutputDir string   `json:"output_dir"`
	Files     []string `json:"files"`
}

func Share(opts ShareOptions) (ShareResult, error) {
	resolved, err := bundle.Resolve(opts.BundleOrDomain)
	if err != nil {
		return ShareResult{}, err
	}
	bundleDir := resolved.Path
	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = filepath.Join(bundleDir, "share")
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return ShareResult{}, err
	}
	flows, err := adapter.LoadJSONL(filepath.Join(bundleDir, "flows.jsonl"))
	if err != nil {
		return ShareResult{}, err
	}
	domain := opts.Domain
	if domain == "" {
		domain = resolved.Domain
	}
	if domain == "" {
		domain = resolved.SafeName
	}
	domain = domainFromSession(bundleDir, domain)
	inventory := BuildInventory(flows, domain)

	files := []string{}
	specDoc, err := spec.Generate(spec.FilterAPIFlows(flows), domain, auth.Detect(flows), spec.Options{InferSchemes: true, IncludeExamples: false})
	if err != nil && !errors.Is(err, spec.ErrNoValidAPIFlows) {
		return ShareResult{}, err
	}
	if err == nil {
		specData, err := spec.MarshalAndValidate(specDoc, "yaml")
		if err != nil {
			return ShareResult{}, err
		}
		if err := os.WriteFile(filepath.Join(outputDir, "spec.yaml"), specData, 0o600); err != nil {
			return ShareResult{}, err
		}
		files = append(files, "spec.yaml")
	}

	if err := WriteInventory(filepath.Join(outputDir, "inventory.json"), inventory); err != nil {
		return ShareResult{}, err
	}
	files = append(files, "inventory.json")

	if err := os.WriteFile(filepath.Join(outputDir, "report.md"), Markdown(inventory), 0o600); err != nil {
		return ShareResult{}, err
	}
	files = append(files, "report.md")

	if copied, err := copySession(bundleDir, outputDir); err != nil {
		return ShareResult{}, err
	} else if copied {
		files = append(files, "session.json")
	}

	return ShareResult{OutputDir: outputDir, Files: files}, nil
}

func copySession(bundleDir string, outputDir string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(bundleDir, "session.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, os.WriteFile(filepath.Join(outputDir, "session.json"), data, 0o600)
}

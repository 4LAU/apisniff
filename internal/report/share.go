package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/capture"
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
	bundleDir, err := resolveBundleDir(opts.BundleOrDomain)
	if err != nil {
		return ShareResult{}, err
	}
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
	domain := domainFromSession(bundleDir, opts.Domain)
	inventory := BuildInventory(flows, domain)

	files := []string{}
	specDoc := spec.Generate(spec.FilterAPIFlows(flows), domain, auth.Detect(flows), spec.Options{InferSchemes: true, IncludeExamples: false})
	specData, err := spec.Marshal(specDoc, "yaml")
	if err != nil {
		return ShareResult{}, err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "spec.yaml"), specData, 0o600); err != nil {
		return ShareResult{}, err
	}
	files = append(files, "spec.yaml")

	if err := WriteInventory(filepath.Join(outputDir, "inventory.json"), inventory); err != nil {
		return ShareResult{}, err
	}
	files = append(files, "inventory.json")

	if err := os.WriteFile(filepath.Join(outputDir, "report.md"), Markdown(inventory), 0o600); err != nil {
		return ShareResult{}, err
	}
	files = append(files, "report.md")

	if err := copySession(bundleDir, outputDir); err != nil {
		return ShareResult{}, err
	}
	files = append(files, "session.json")

	return ShareResult{OutputDir: outputDir, Files: files}, nil
}

func resolveBundleDir(bundleOrDomain string) (string, error) {
	if bundleOrDomain == "" {
		return "", fmt.Errorf("bundle or domain is required")
	}
	if info, err := os.Stat(bundleOrDomain); err == nil && info.IsDir() {
		return bundleOrDomain, nil
	}
	safe := strings.NewReplacer(".", "-", "/", "-").Replace(bundleOrDomain)
	matches, err := filepath.Glob(filepath.Join(capture.CapturesDir(), safe+"_*"))
	if err != nil {
		return "", err
	}
	var dirs []string
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil && info.IsDir() {
			dirs = append(dirs, match)
		}
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("no capture bundle found for %s", bundleOrDomain)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	return dirs[0], nil
}

func copySession(bundleDir string, outputDir string) error {
	data, err := os.ReadFile(filepath.Join(bundleDir, "session.json"))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "session.json"), data, 0o600)
}

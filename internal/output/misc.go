package output

import "fmt"

type ReconResult struct {
	Domain     string
	BundleDir  string
	FlowsPath  string
	KeptFlows  int
	TotalFlows int
}

type SpecStatusResult struct {
	Domain            string
	Format            string
	OutputPath        string
	SurfaceOutputPath string
	Paths             int
	Operations        int
}

type ShareResult struct {
	OutputDir string   `json:"output_dir"`
	Files     []string `json:"files"`
}

func WriteRecon(cfg Config, result ReconResult) error {
	s := newStyles(cfg)
	completion := fmt.Sprintf("%s captured %d flows", s.successIcon(), result.KeptFlows)
	if result.TotalFlows > 0 && result.TotalFlows != result.KeptFlows {
		completion = fmt.Sprintf("%s (%d observed)", completion, result.TotalFlows)
	}

	lines := []string{
		s.headerBox("apisniff recon", result.Domain),
		completion,
		"",
		s.section("Bundle"),
		s.kv("directory", result.BundleDir),
		s.kv("flows", result.FlowsPath),
	}
	return s.writeLines(lines...)
}

func WriteSpecStatus(cfg Config, result SpecStatusResult) error {
	s := newStyles(cfg)
	lines := []string{
		s.headerBox("apisniff spec", result.Domain),
	}
	if result.OutputPath != "" {
		lines = append(lines, fmt.Sprintf("%s wrote %s", s.successIcon(), result.OutputPath))
	} else {
		lines = append(lines, fmt.Sprintf("%s generated spec", s.successIcon()))
	}
	if result.Format != "" {
		lines = append(lines, s.kv("format", result.Format))
	}
	if result.SurfaceOutputPath != "" {
		lines = append(lines, s.kv("surface", result.SurfaceOutputPath))
	}
	if result.Paths > 0 {
		lines = append(lines, s.kv("paths", fmt.Sprintf("%d", result.Paths)))
	}
	if result.Operations > 0 {
		lines = append(lines, s.kv("operations", fmt.Sprintf("%d", result.Operations)))
	}
	return s.writeLines(lines...)
}

func WriteShare(cfg Config, result ShareResult) error {
	s := newStyles(cfg)
	lines := []string{
		s.headerBox("apisniff share", result.OutputDir),
		fmt.Sprintf("%s exported %d files", s.successIcon(), len(result.Files)),
	}
	if len(result.Files) > 0 {
		lines = append(lines, "")
		for _, file := range result.Files {
			lines = append(lines, "  "+file)
		}
	}
	return s.writeLines(lines...)
}

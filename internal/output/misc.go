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
	lines := []string{
		s.title("apisniff recon"),
		s.summary("captured", fmt.Sprintf("%d flows", result.KeptFlows)),
	}
	if result.TotalFlows > 0 && result.TotalFlows != result.KeptFlows {
		lines = append(lines, s.summary("observed", fmt.Sprintf("%d flows", result.TotalFlows)))
	}
	if result.Domain != "" {
		lines = append(lines, s.summary("domain", result.Domain))
	}
	lines = append(lines,
		"",
		s.header("Bundle"),
		s.summary("directory", result.BundleDir),
		s.summary("flows", result.FlowsPath),
	)
	return s.writeLines(lines...)
}

func WriteSpecStatus(cfg Config, result SpecStatusResult) error {
	s := newStyles(cfg)
	lines := []string{s.title("apisniff spec")}
	if result.Domain != "" {
		lines = append(lines, s.summary("domain", result.Domain))
	}
	if result.Format != "" {
		lines = append(lines, s.summary("format", result.Format))
	}
	if result.OutputPath != "" {
		lines = append(lines, s.summary("wrote", result.OutputPath))
	}
	if result.SurfaceOutputPath != "" {
		lines = append(lines, s.summary("surface", result.SurfaceOutputPath))
	}
	if result.Paths > 0 {
		lines = append(lines, s.summary("paths", fmt.Sprintf("%d", result.Paths)))
	}
	if result.Operations > 0 {
		lines = append(lines, s.summary("operations", fmt.Sprintf("%d", result.Operations)))
	}
	return s.writeLines(lines...)
}

func WriteShare(cfg Config, result ShareResult) error {
	s := newStyles(cfg)
	lines := []string{
		s.title("apisniff share"),
		s.summary("output", result.OutputDir),
	}
	if len(result.Files) > 0 {
		lines = append(lines, "", s.header("Files"))
		for _, file := range result.Files {
			lines = append(lines, "  "+file)
		}
	}
	return s.writeLines(lines...)
}

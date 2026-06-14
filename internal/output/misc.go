package output

import (
	"fmt"
	"strings"

	"github.com/4LAU/apisniff/internal/model"
)

type ReconResult struct {
	Domain              string
	BundleDir           string
	FlowsPath           string
	FilteredPath        string
	KeptFlows           int
	TotalFlows          int
	FilteredFlows       int
	Defenses            []model.VendorMatch
	UnattributedAntibot int
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
	var details []string
	if result.TotalFlows > 0 && result.TotalFlows != result.KeptFlows {
		details = append(details, fmt.Sprintf("%d observed", result.TotalFlows))
	}
	if result.FilteredFlows > 0 {
		details = append(details, fmt.Sprintf("%d filtered", result.FilteredFlows))
	}
	if len(details) > 0 {
		completion = fmt.Sprintf("%s (%s)", completion, strings.Join(details, ", "))
	}

	lines := []string{
		s.headerBox("apisniff recon", result.Domain),
		completion,
		"",
		s.header("Bundle"),
		s.kv("directory", result.BundleDir),
		s.kv("flows", result.FlowsPath),
	}
	if result.FilteredPath != "" {
		lines = append(lines, s.kv("filtered", result.FilteredPath))
	}
	if len(result.Defenses) > 0 || result.UnattributedAntibot > 0 {
		lines = append(lines, "", s.panel("Defenses observed", defensePanelBody(result)))
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

func defensePanelBody(result ReconResult) string {
	var lines []string
	for _, m := range result.Defenses {
		vendor := strings.ReplaceAll(m.Vendor, "_", " ")
		sigs := make([]string, 0, len(m.Signals))
		for _, label := range m.Signals {
			parts := strings.SplitN(label, ":", 3)
			if len(parts) == 3 {
				sigs = append(sigs, parts[2])
			} else {
				sigs = append(sigs, label)
			}
		}
		line := fmt.Sprintf("%s (%s)", vendor, m.Confidence)
		if len(sigs) > 0 {
			line += " — " + strings.Join(sigs, ", ")
		}
		lines = append(lines, line)
	}
	if result.UnattributedAntibot > 0 {
		lines = append(lines, fmt.Sprintf("unattributed antibot (%d flows)", result.UnattributedAntibot))
	}
	return strings.Join(lines, "\n")
}

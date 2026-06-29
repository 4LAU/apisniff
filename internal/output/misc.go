package output

import (
	"fmt"
	"sort"
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

	DurationSeconds float64

	// GraphQL catalog counts, printed only when GraphQLOperations > 0.
	GraphQLOperations    int
	GraphQLFlows         int
	GraphQLCapturedQuery int
	GraphQLPersistedHash int
}

type SpecStatusResult struct {
	Domain            string
	Format            string
	OutputPath        string
	SurfaceOutputPath string
	Paths             int
	Operations        int
	MethodCounts      map[string]int

	ExcludedCount        int
	ExcludedContentTypes map[string]int

	GraphQLOperations int
	GraphQLFlows      int
}

type ShareResult struct {
	OutputDir string   `json:"output_dir"`
	Files     []string `json:"files"`
}

func WriteRecon(cfg Config, result ReconResult) error {
	s := newStyles(cfg)
	completion := fmt.Sprintf("%s captured %d flows", s.successIcon(), result.KeptFlows)
	if result.DurationSeconds > 0 {
		completion += s.faint(fmt.Sprintf(" in %.1fs", result.DurationSeconds))
	}
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
		s.kv("directory", s.faint(result.BundleDir)),
		s.kv("flows", s.faint(result.FlowsPath)),
	}
	if result.FilteredPath != "" {
		lines = append(lines, s.kv("filtered", s.faint(result.FilteredPath)))
	}
	if len(result.Defenses) > 0 || result.UnattributedAntibot > 0 {
		lines = append(lines, "", s.panel("Defenses observed", defensePanelBody(result)))
	}
	lines = append(lines, graphQLSummaryLines(
		result.GraphQLOperations,
		result.GraphQLFlows,
		result.GraphQLCapturedQuery,
		result.GraphQLPersistedHash,
	)...)
	return s.writeLines(lines...)
}

// graphQLSummaryLines renders the two-line catalog block shared by the recon
// and analyze paths, only when operations exist.
func graphQLSummaryLines(operations, flows, capturedQuery, persistedHash int) []string {
	if operations <= 0 {
		return nil
	}
	return []string{
		"",
		fmt.Sprintf("GraphQL: %d operations cataloged from %d flows → graphql-operations.json",
			operations, flows),
		fmt.Sprintf("         (%d with captured query text, %d persisted-hash only)",
			capturedQuery, persistedHash),
	}
}

func WriteSpecStatus(cfg Config, result SpecStatusResult) error {
	s := newStyles(cfg)
	lines := []string{
		s.headerBox("apisniff spec", result.Domain),
	}
	if result.OutputPath != "" {
		lines = append(lines, fmt.Sprintf("%s wrote %s", s.successIcon(), s.faint(result.OutputPath)))
	} else {
		lines = append(lines, fmt.Sprintf("%s generated spec", s.successIcon()))
	}
	if result.Paths > 0 || result.Operations > 0 {
		summary := fmt.Sprintf("  %d paths", result.Paths)
		sep := " · "
		if !s.cfg.Unicode {
			sep = ", "
		}
		summary += fmt.Sprintf("%s%d operations", sep, result.Operations)
		lines = append(lines, "", summary)
	}
	if badges := s.methodBreakdown(result.MethodCounts); badges != "" {
		lines = append(lines, badges)
	}
	if result.GraphQLOperations > 0 {
		lines = append(lines, fmt.Sprintf("  GraphQL: %d operations from %d flows",
			result.GraphQLOperations, result.GraphQLFlows))
	}
	if result.ExcludedCount > 0 {
		line := fmt.Sprintf("%s %d captured endpoint(s) not in spec", s.warnIcon(), result.ExcludedCount)
		if breakdown := contentTypeBreakdown(result.ExcludedContentTypes); breakdown != "" {
			line += fmt.Sprintf(" (%s)", breakdown)
		}
		if result.SurfaceOutputPath == "" {
			line += " — run with --surface-output to list them"
		}
		lines = append(lines, "", line)
	}
	if result.Format != "" {
		lines = append(lines, "", s.kv("format", s.faint(result.Format)))
	}
	if result.SurfaceOutputPath != "" {
		lines = append(lines, s.kv("surface", s.faint(result.SurfaceOutputPath)))
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

// contentTypeBreakdown renders a stable "2 text/html, 1 text/csv" summary.
func contentTypeBreakdown(counts map[string]int) string {
	types := make([]string, 0, len(counts))
	for ct := range counts {
		types = append(types, ct)
	}
	sort.Strings(types)
	parts := make([]string, 0, len(types))
	for _, ct := range types {
		parts = append(parts, fmt.Sprintf("%d %s", counts[ct], ct))
	}
	return strings.Join(parts, ", ")
}

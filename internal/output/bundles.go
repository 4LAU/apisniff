package output

import (
	"fmt"
	"strings"
	"time"
)

type BundleSummary struct {
	Path        string    `json:"path"`
	Domain      string    `json:"domain,omitempty"`
	SafeName    string    `json:"safe_name,omitempty"`
	CapturedAt  time.Time `json:"captured_at"`
	SizeBytes   int64     `json:"size_bytes"`
	FlowCount   int       `json:"flow_count"`
	Credentials []string  `json:"credentials,omitempty"`
}

type BundlesResult struct {
	CapturesDir        string          `json:"captures_dir"`
	TotalSizeBytes     int64           `json:"total_size_bytes"`
	IncludeCredentials bool            `json:"-"`
	Bundles            []BundleSummary `json:"bundles"`
}

type CleanResult struct {
	Deleted        []BundleSummary `json:"deleted"`
	TotalSizeBytes int64           `json:"total_size_bytes"`
	DryRun         bool            `json:"dry_run"`
}

func WriteBundles(cfg Config, result BundlesResult) error {
	s := newStyles(cfg)
	lines := []string{s.headerBox("apisniff bundles", "")}
	if len(result.Bundles) == 0 {
		message := "No capture bundles found."
		if result.CapturesDir != "" {
			message = fmt.Sprintf("No capture bundles found in %s.", result.CapturesDir)
		}
		lines = append(lines, message)
		return s.writeLines(lines...)
	}

	rows := make([][]string, 0, len(result.Bundles))
	for _, bundle := range result.Bundles {
		row := []string{
			firstNonEmpty(bundle.Domain, bundle.SafeName, "-"),
			bundle.CapturedAt.Local().Format("2006-01-02 15:04"),
			fmt.Sprintf("%d", bundle.FlowCount),
			humanBytes(bundle.SizeBytes),
			bundle.Path,
		}
		if result.IncludeCredentials {
			creds := "-"
			if len(bundle.Credentials) > 0 {
				creds = strings.Join(bundle.Credentials, ", ")
			}
			row = append(row[:4], append([]string{creds}, row[4:]...)...)
		}
		rows = append(rows, row)
	}
	headers := []string{"Domain", "Captured", "Flows", "Size", "Path"}
	if result.IncludeCredentials {
		headers = []string{"Domain", "Captured", "Flows", "Size", "Credentials", "Path"}
	}
	lines = append(lines, fmt.Sprintf("%d capture bundle(s) in %s (%s total)", len(result.Bundles), result.CapturesDir, humanBytes(result.TotalSizeBytes)))
	lines = append(lines, "", s.simpleTable(headers, rows))
	return s.writeLines(lines...)
}

func WriteClean(cfg Config, result CleanResult) error {
	s := newStyles(cfg)
	if len(result.Deleted) == 0 {
		return s.writeLines(s.headerBox("apisniff clean", ""), "No bundles match the given criteria")
	}
	action := "deleted"
	if result.DryRun {
		action = "would delete"
	}
	lines := []string{
		s.headerBox("apisniff clean", ""),
		fmt.Sprintf("%s %s %d bundle(s) (%s)", s.successIcon(), action, len(result.Deleted), humanBytes(result.TotalSizeBytes)),
	}
	lines = append(lines, "", cleanTable(s, result.Deleted))
	return s.writeLines(lines...)
}

func WriteCleanConfirmation(cfg Config, result CleanResult) error {
	s := newStyles(cfg)
	if len(result.Deleted) == 0 {
		return nil
	}
	lines := []string{
		"The following bundles will be deleted:",
		"",
		cleanTable(s, result.Deleted),
		"",
		fmt.Sprintf("Delete %d bundle(s) (%s)? [y/N] ", len(result.Deleted), humanBytes(result.TotalSizeBytes)),
	}
	return s.writeLines(lines...)
}

func cleanTable(s styles, bundles []BundleSummary) string {
	rows := make([][]string, 0, len(bundles))
	for _, bundle := range bundles {
		rows = append(rows, []string{
			firstNonEmpty(bundle.Domain, bundle.SafeName, "-"),
			bundle.CapturedAt.Local().Format("2006-01-02 15:04"),
			humanBytes(bundle.SizeBytes),
			fmt.Sprintf("%d", bundle.FlowCount),
			bundle.Path,
		})
	}
	return s.simpleTable([]string{"Domain", "Captured", "Size", "Flows", "Path"}, rows)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func humanBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

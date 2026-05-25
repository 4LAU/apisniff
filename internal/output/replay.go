package output

import (
	"fmt"

	"github.com/4LAU/apisniff-go/internal/replay"
)

func WriteReplay(cfg Config, summary replay.Summary) error {
	s := newStyles(cfg)
	if summary.Mode == "dry_run" {
		return writeReplayDryRun(s, summary)
	}

	total := 0
	for _, count := range summary.Summary {
		total += count
	}
	lines := []string{
		s.title("apisniff replay"),
		s.summary("flows", fmt.Sprintf("%d", total)),
	}
	if summary.Domain != "" {
		lines = append(lines, s.summary("domain", summary.Domain))
	}
	lines = append(lines, "", s.header("Summary"))
	for _, category := range []string{"match", "drift", "auth_expired", "blocked", "error"} {
		if count := summary.Summary[category]; count > 0 {
			lines = append(lines, s.summary(category, fmt.Sprintf("%d", count)))
		}
	}
	if len(summary.Results) > 0 {
		lines = append(lines, "", s.header("Results"))
		for _, result := range summary.Results {
			status := "-"
			if result.ReplayedStatus != 0 {
				status = fmt.Sprintf("%d -> %d", result.OriginalStatus, result.ReplayedStatus)
			}
			detail := result.Category
			if result.Error != "" {
				detail += ": " + result.Error
			}
			lines = append(lines, s.row(s.methodBadge(result.Method), result.Path, s.statusBadge(status)+" "+detail))
		}
	}
	return s.writeLines(lines...)
}

func writeReplayDryRun(s styles, summary replay.Summary) error {
	lines := []string{
		s.title("apisniff replay dry run"),
		s.summary("safe", fmt.Sprintf("%d", summary.Summary["safe"])),
		s.summary("unsafe", fmt.Sprintf("%d", summary.Summary["unsafe"])),
		s.summary("total", fmt.Sprintf("%d", summary.Summary["total"])),
	}
	if summary.Domain != "" {
		lines = append(lines, s.summary("domain", summary.Domain))
	}
	if len(summary.Endpoints) > 0 {
		lines = append(lines, "", s.header("Endpoints"))
		for _, endpoint := range summary.Endpoints {
			lines = append(lines, "  "+endpoint)
		}
	}
	return s.writeLines(lines...)
}

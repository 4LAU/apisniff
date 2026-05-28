package output

import (
	"fmt"
	"strings"

	"github.com/4LAU/apisniff/internal/replay"
)

func WriteReplay(cfg Config, summary replay.Summary) error {
	s := newStyles(cfg)
	if summary.Mode == "dry_run" {
		return writeReplayDryRun(s, summary)
	}

	lines := []string{
		s.headerBox("apisniff replay", summary.Domain),
		"",
		fmt.Sprintf("  %d flows replayed", replayTotal(summary)),
	}

	if len(summary.Results) > 0 {
		rows := make([][]string, 0, len(summary.Results))
		for _, result := range summary.Results {
			status := replayStatus(result)
			if !s.cfg.Unicode {
				status = replayStatusASCII(result)
			}
			detail := s.resultLabel(result.Category)
			if result.Error != "" {
				detail += " " + s.faint(result.Error)
			}
			rows = append(rows, []string{
				s.methodBadge(result.Method),
				result.Path,
				s.statusText(status),
				detail,
			})
		}
		lines = append(lines, "", s.simpleTable([]string{"Method", "Path", "Status", "Result"}, rows))
	}

	lines = append(lines, "", s.section("Summary"))
	for _, line := range replaySummaryLines(s, summary, []string{"match", "drift", "auth_expired", "blocked", "error"}) {
		lines = append(lines, line)
	}
	return s.writeLines(lines...)
}

func writeReplayDryRun(s styles, summary replay.Summary) error {
	lines := []string{
		s.headerBox("apisniff replay dry run", summary.Domain),
		"",
		strings.Join([]string{
			compactKV(s, "safe", fmt.Sprintf("%d", summary.Summary["safe"])),
			compactKV(s, "unsafe", fmt.Sprintf("%d", summary.Summary["unsafe"])),
			compactKV(s, "total", fmt.Sprintf("%d", summary.Summary["total"])),
		}, "  "),
	}
	if len(summary.Endpoints) > 0 {
		lines = append(lines, "", s.section("Endpoints"))
		for _, endpoint := range summary.Endpoints {
			lines = append(lines, "  "+endpoint)
		}
	}
	return s.writeLines(lines...)
}

func replayTotal(summary replay.Summary) int {
	total := 0
	for _, count := range summary.Summary {
		total += count
	}
	if total == 0 {
		total = len(summary.Results)
	}
	return total
}

func replayStatus(result replay.Result) string {
	arrow := " → "
	if result.ReplayedStatus == 0 {
		return fmt.Sprintf("%d%s-", result.OriginalStatus, arrow)
	}
	return fmt.Sprintf("%d%s%d", result.OriginalStatus, arrow, result.ReplayedStatus)
}

func replayStatusASCII(result replay.Result) string {
	if result.ReplayedStatus == 0 {
		return fmt.Sprintf("%d -> -", result.OriginalStatus)
	}
	return fmt.Sprintf("%d -> %d", result.OriginalStatus, result.ReplayedStatus)
}

func replaySummaryLines(s styles, summary replay.Summary, categories []string) []string {
	var lines []string
	for _, category := range categories {
		count := summary.Summary[category]
		if count == 0 {
			continue
		}
		lines = append(lines, s.kv(category, fmt.Sprintf("%d", count)))
	}
	if len(lines) == 0 {
		return []string{s.kv("summary", "none")}
	}
	return lines
}

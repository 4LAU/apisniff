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

	lines = append(lines, replayMergeSection(s, summary.Merges)...)

	lines = append(lines, "", s.header("Summary"))
	lines = append(lines, replaySummaryLines(s, summary, []string{"match", "drift", "auth_expired", "blocked", "error"})...)
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
		lines = append(lines, "", s.header("Endpoints"))
		for _, endpoint := range summary.Endpoints {
			lines = append(lines, "  "+endpoint)
		}
	}
	lines = append(lines, replayMergeSection(s, summary.Merges)...)
	return s.writeLines(lines...)
}

// replayMergeSection renders the routes that opaque-ID templating collapsed into
// a single replay key. It is the user-facing half of the "never silent" backstop:
// if a shape rule over-collapses a real route, the operator sees the merge here
// instead of the route vanishing from the run.
func replayMergeSection(s styles, merges []replay.DedupMerge) []string {
	if len(merges) == 0 {
		return nil
	}
	lines := []string{"", s.header("Merged routes")}
	for _, m := range merges {
		count := s.faint(fmt.Sprintf("(%d paths merged)", len(m.Paths)))
		lines = append(lines, fmt.Sprintf("  %s %s  %s", m.Method, m.Key, count))
	}
	return lines
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

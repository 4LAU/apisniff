package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/4LAU/apisniff/internal/bundle"
	"github.com/4LAU/apisniff/internal/output"
	"github.com/spf13/cobra"
)

var (
	bundleDelete = bundle.Delete
	nowUTC       = func() time.Time { return time.Now().UTC() }
)

func newCleanCommand() *cobra.Command {
	var (
		olderThanRaw string
		domain       string
		all          bool
		yes          bool
		dryRun       bool
		jsonOutput   bool
	)
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Delete capture bundles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if olderThanRaw == "" && domain == "" && !all {
				return errors.New("clean requires at least one of --older-than, --domain, or --all")
			}
			olderThan, err := parseOlderThan(olderThanRaw)
			if err != nil {
				return err
			}

			bundles, err := bundleList()
			if err != nil {
				return err
			}
			matches := filterCleanBundles(bundles, cleanFilters{
				OlderThan: olderThan,
				Domain:    domain,
				All:       all,
				Now:       nowUTC(),
			})
			planned := make([]output.BundleSummary, 0, len(matches))
			var plannedSize int64
			for _, match := range matches {
				summary := bundleSummary(match)
				planned = append(planned, summary)
				plannedSize += summary.SizeBytes
			}
			preview := output.CleanResult{
				DryRun:         dryRun,
				Deleted:        planned,
				TotalSizeBytes: plannedSize,
			}

			if len(matches) > 0 && !dryRun {
				if !yes && !stdinIsInteractive(cmd.InOrStdin()) {
					return errors.New("confirmation required; rerun with --yes or --dry-run")
				}
				if !yes {
					if err := output.WriteCleanConfirmation(humanOutputConfig(cmd), preview); err != nil {
						return err
					}
					ok, err := confirmClean(cmd.InOrStdin())
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("clean canceled")
					}
				}
			}

			result := output.CleanResult{
				DryRun:  dryRun,
				Deleted: make([]output.BundleSummary, 0, len(matches)),
			}
			if !dryRun {
				for i, match := range matches {
					if err := bundleDelete(match); err != nil {
						return err
					}
					result.Deleted = append(result.Deleted, planned[i])
					result.TotalSizeBytes += planned[i].SizeBytes
				}
			} else {
				result.Deleted = planned
				result.TotalSizeBytes = plannedSize
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}
			return output.WriteClean(humanOutputConfig(cmd), result)
		},
	}
	cmd.Flags().StringVar(&olderThanRaw, "older-than", "", "delete bundles older than this age (for example 30d or 720h)")
	cmd.Flags().StringVar(&domain, "domain", "", "delete bundles for this domain")
	cmd.Flags().BoolVar(&all, "all", false, "delete all bundles")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deletion")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be deleted")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	return cmd
}

type cleanFilters struct {
	OlderThan time.Duration
	Domain    string
	All       bool
	Now       time.Time
}

func filterCleanBundles(candidates []bundle.Bundle, filters cleanFilters) []bundle.Bundle {
	matches := make([]bundle.Bundle, 0, len(candidates))
	cutoff := filters.Now.Add(-filters.OlderThan)
	safeDomain := bundle.SafeName(filters.Domain)
	for _, candidate := range candidates {
		if filters.Domain != "" && candidate.Domain != filters.Domain && candidate.SafeName != filters.Domain && candidate.SafeName != safeDomain {
			continue
		}
		if filters.OlderThan > 0 && !candidate.CapturedAt.Before(cutoff) {
			continue
		}
		if !filters.All && filters.Domain == "" && filters.OlderThan == 0 {
			continue
		}
		matches = append(matches, candidate)
	}
	return matches
}

func parseOlderThan(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid --older-than %q", value)
		}
		duration := time.Duration(days) * 24 * time.Hour
		if duration <= 0 {
			return 0, errors.New("--older-than must be greater than zero")
		}
		return duration, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid --older-than %q", value)
	}
	if duration <= 0 {
		return 0, errors.New("--older-than must be greater than zero")
	}
	return duration, nil
}

func stdinIsInteractive(r io.Reader) bool {
	file, ok := r.(*os.File)
	if !ok {
		return true
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func confirmClean(r io.Reader) (bool, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "yes" || answer == "y", nil
}

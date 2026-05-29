package cli

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/bundle"
	"github.com/4LAU/apisniff/internal/output"
	"github.com/spf13/cobra"
)

var (
	bundleList = bundle.List
	bundleDir  = bundle.Dir
	loadJSONL  = adapter.LoadJSONL
)

func newBundlesCommand() *cobra.Command {
	var (
		jsonOutput     bool
		showCredential bool
	)
	cmd := &cobra.Command{
		Use:   "bundles",
		Short: "List capture bundles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			bundles, err := bundleList()
			if err != nil {
				return err
			}
			result := output.BundlesResult{
				CapturesDir:        bundleDir(),
				IncludeCredentials: showCredential,
				Bundles:            make([]output.BundleSummary, 0, len(bundles)),
			}
			for _, candidate := range bundles {
				summary := bundleSummary(candidate)
				if showCredential {
					credentials, err := detectBundleCredentials(candidate)
					if err != nil {
						return err
					}
					summary.Credentials = credentials
				}
				result.Bundles = append(result.Bundles, summary)
				result.TotalSizeBytes += summary.SizeBytes
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}
			return output.WriteBundles(humanOutputConfig(cmd), result)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&showCredential, "credentials", false, "inspect flows.jsonl for credential patterns")
	return cmd
}

func bundleSummary(candidate bundle.Bundle) output.BundleSummary {
	return output.BundleSummary{
		Path:       candidate.Path,
		Domain:     candidate.Domain,
		SafeName:   candidate.SafeName,
		CapturedAt: candidate.CapturedAt,
		SizeBytes:  candidate.SizeBytes,
		FlowCount:  candidate.FlowCount,
	}
}

func detectBundleCredentials(candidate bundle.Bundle) ([]string, error) {
	flows, err := loadJSONL(filepath.Join(candidate.Path, "flows.jsonl"))
	if err != nil {
		return nil, err
	}
	return credentialLabels(auth.Detect(flows)), nil
}

func credentialLabels(patterns []auth.Pattern) []string {
	seen := map[string]struct{}{}
	for _, pattern := range patterns {
		label := credentialLabel(pattern.AuthType)
		if label == "" {
			continue
		}
		seen[label] = struct{}{}
	}
	labels := make([]string, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool {
		return credentialRank(labels[i]) < credentialRank(labels[j])
	})
	return labels
}

func credentialLabel(authType string) string {
	switch strings.ToLower(authType) {
	case "bearer":
		return "bearer"
	case "basic":
		return "basic"
	case "api_key_header", "api_key_query":
		return "api_key"
	case "session_cookie":
		return "cookies"
	case "token_endpoint":
		return "oauth"
	default:
		return ""
	}
}

func credentialRank(label string) int {
	switch label {
	case "bearer":
		return 0
	case "basic":
		return 1
	case "api_key":
		return 2
	case "cookies":
		return 3
	case "oauth":
		return 4
	default:
		return 99
	}
}

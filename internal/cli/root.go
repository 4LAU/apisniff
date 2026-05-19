package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/4LAU/apisniff-go/internal/adapter"
	"github.com/4LAU/apisniff-go/internal/auth"
	"github.com/4LAU/apisniff-go/internal/capture"
	"github.com/4LAU/apisniff-go/internal/model"
	"github.com/4LAU/apisniff-go/internal/output"
	"github.com/4LAU/apisniff-go/internal/probe"
	"github.com/4LAU/apisniff-go/internal/replay"
	"github.com/4LAU/apisniff-go/internal/report"
	"github.com/4LAU/apisniff-go/internal/spec"
	"github.com/spf13/cobra"
)

func Execute() error {
	root := newRootCommand()
	return root.Execute()
}

type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ",") }
func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}
func (h *headerFlags) Type() string { return "header" }

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:          "apisniff",
		Short:        "One tool for API recon",
		SilenceUsage: true,
	}
	root.AddCommand(newProbeCommand())
	root.AddCommand(newReconCommand())
	root.AddCommand(newAnalyzeCommand())
	root.AddCommand(newReplayCommand())
	root.AddCommand(newSpecCommand())
	root.AddCommand(newShareCommand())
	return root
}

func newProbeCommand() *cobra.Command {
	var (
		jsonOutput  bool
		proxyURL    string
		headers     headerFlags
		cookie      string
		insecure    bool
		impersonate string
	)
	cmd := &cobra.Command{
		Use:   "probe [URL | rate URL]",
		Short: "Defense preflight",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 || (len(args) == 2 && args[0] == "rate") {
				return nil
			}
			return errors.New("usage: apisniff probe URL or apisniff probe rate URL")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if args[0] == "rate" {
				target = args[1]
			}
			parsedHeaders, err := parseHeaders(headers)
			if err != nil {
				return err
			}
			assessment, err := probe.Run(cmd.Context(), target, probe.Options{
				Proxy:       proxyURL,
				Headers:     parsedHeaders,
				Cookie:      cookie,
				Insecure:    insecure,
				Impersonate: impersonate,
				Timeout:     15 * time.Second,
			})
			if err != nil {
				return err
			}
			return output.WriteProbe(cmd.OutOrStdout(), assessment, jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "route probes through proxy")
	cmd.Flags().VarP(&headers, "header", "H", "extra header (key:value)")
	cmd.Flags().StringVar(&cookie, "cookie", "", "Cookie header value")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification")
	cmd.Flags().StringVar(&impersonate, "impersonate", "chrome", "TLS profile")
	return cmd
}

func newReconCommand() *cobra.Command {
	var (
		jsonOutput bool
		proxyURL   string
		port       int
		mode       string
		attachURL  string
		headless   bool
		wait       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "recon DOMAIN",
		Short: "Capture traffic with Chrome DevTools Protocol",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if proxyURL != "" {
				return errors.New("--proxy as an upstream proxy is not implemented; use --mode proxy to run the apisniff MITM proxy")
			}
			domain, launchURL := normalizeTarget(args[0])
			result, err := capture.Capture(cmd.Context(), capture.Config{
				Domain:    domain,
				URL:       launchURL,
				Mode:      mode,
				Port:      port,
				AttachURL: attachURL,
				Headless:  headless,
				Wait:      wait,
			})
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "captured %d flows -> %s\n", result.Stats.KeptFlows, result.BundleDir)
			fmt.Fprintf(cmd.OutOrStdout(), "flows: %s\n", result.FlowsPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "reserved for future upstream proxy chaining")
	cmd.Flags().IntVar(&port, "port", 9222, "CDP or proxy port")
	cmd.Flags().StringVar(&mode, "mode", "cdp-launch", "capture mode: cdp-launch, cdp-attach, proxy")
	cmd.Flags().StringVar(&attachURL, "remote-url", "", "CDP URL for cdp-attach")
	cmd.Flags().BoolVar(&headless, "headless", false, "launch Chrome headless")
	cmd.Flags().DurationVar(&wait, "wait", 8*time.Second, "extra wait after navigation")
	return cmd
}

func newAnalyzeCommand() *cobra.Command {
	var (
		domain       string
		jsonOutput   bool
		outputDir    string
		fetchGraphQL bool
	)
	cmd := &cobra.Command{
		Use:   "analyze INPUT_FILE",
		Short: "Load captured JSONL flows",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = outputDir
			_ = fetchGraphQL
			flows, inputFormat, err := adapter.LoadFlows(args[0])
			if err != nil {
				return err
			}
			if inputFormat == "unknown" {
				return fmt.Errorf("unknown input format for %s", args[0])
			}
			result := output.AnalyzeResult{
				SchemaVersion: 1,
				Domain:        domain,
				TotalFlows:    len(flows),
				TopEndpoints:  summarizeEndpoints(flows, 15),
				AuthPatterns:  auth.Detect(flows),
				Cookies:       auth.ExtractCookies(flows),
			}
			if jsonOutput {
				result.Flows = flows
			}
			return output.WriteAnalyze(cmd.OutOrStdout(), result, jsonOutput)
		},
	}
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "target domain")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "directory to write bundle")
	cmd.Flags().BoolVar(&fetchGraphQL, "fetch-graphql", false, "fetch GraphQL schema")
	return cmd
}

func newReplayCommand() *cobra.Command {
	var (
		filter        string
		timeout       time.Duration
		cookieFile    string
		headers       headerFlags
		jsonOutput    bool
		outputFile    string
		dryRun        bool
		includeUnsafe bool
		insecure      bool
		impersonate   string
	)
	cmd := &cobra.Command{
		Use:   "replay BUNDLE|DOMAIN|FLOWS_JSONL",
		Short: "Replay captured flows safely",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedHeaders, err := parseHeaders(headers)
			if err != nil {
				return err
			}
			summary, err := replay.Run(cmd.Context(), replay.Options{
				BundleOrDomain: args[0],
				Filter:         filter,
				Timeout:        timeout,
				CookieFile:     cookieFile,
				Headers:        parsedHeaders,
				Impersonate:    impersonate,
				IncludeUnsafe:  includeUnsafe,
				Insecure:       insecure,
				DryRun:         dryRun,
			})
			if err != nil {
				return err
			}
			if outputFile != "" {
				data, err := json.MarshalIndent(summary, "", "  ")
				if err != nil {
					return err
				}
				if err := os.WriteFile(outputFile, append(data, '\n'), 0o600); err != nil {
					return err
				}
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), summary)
			}
			return writeReplaySummary(cmd.OutOrStdout(), summary)
		},
	}
	cmd.Flags().StringVar(&filter, "filter", "", "glob filter for paths")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "request timeout")
	cmd.Flags().StringVar(&cookieFile, "cookie-file", "", "Netscape cookies.txt path")
	cmd.Flags().VarP(&headers, "header", "H", "extra header (key:value)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "write JSON output")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "list endpoints without replaying")
	cmd.Flags().BoolVar(&includeUnsafe, "include-unsafe", false, "include non-GET/HEAD/OPTIONS methods")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification")
	cmd.Flags().StringVar(&impersonate, "impersonate", "chrome", "TLS profile: chrome or firefox")
	return cmd
}

func newSpecCommand() *cobra.Command {
	var (
		inputFile         string
		format            string
		outputFile        string
		surfaceOutput     string
		includeThirdParty bool
		includeCategory   []string
		includeHost       []string
		inferSchemes      bool
		includeExamples   bool
	)
	cmd := &cobra.Command{
		Use:   "spec DOMAIN",
		Short: "Generate OpenAPI from captured traffic",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = surfaceOutput
			_ = includeThirdParty
			_ = includeCategory
			_ = includeHost
			domain := args[0]
			path := inputFile
			if path == "" {
				latest, err := findLatestBundle(domain)
				if err != nil {
					return err
				}
				path = filepath.Join(latest, "flows.jsonl")
			}
			flows, inputFormat, err := adapter.LoadFlows(path)
			if err != nil {
				return err
			}
			if inputFormat == "unknown" {
				return fmt.Errorf("unknown input format for %s", path)
			}
			apiFlows := spec.FilterAPIFlows(flows)
			doc := spec.Generate(apiFlows, domain, auth.Detect(flows), spec.Options{
				InferSchemes:    inferSchemes,
				IncludeExamples: includeExamples,
			})
			data, err := spec.Marshal(doc, format)
			if err != nil {
				return err
			}
			if outputFile != "" {
				return os.WriteFile(outputFile, data, 0o600)
			}
			_, err = cmd.OutOrStdout().Write(append(data, '\n'))
			return err
		},
	}
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	cmd.Flags().StringVarP(&format, "format", "f", "yaml", "output format: yaml or json")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	cmd.Flags().StringVar(&surfaceOutput, "surface-output", "", "surface output path")
	cmd.Flags().BoolVar(&includeThirdParty, "include-third-party", false, "include third-party flows")
	cmd.Flags().StringArrayVar(&includeCategory, "include-category", nil, "include category")
	cmd.Flags().StringArrayVar(&includeHost, "include-host", nil, "include host")
	cmd.Flags().BoolVar(&inferSchemes, "infer-security-schemes", false, "infer OpenAPI securitySchemes from observed auth")
	cmd.Flags().Bool("no-infer-security-schemes", false, "keep observed auth in extensions only")
	cmd.Flags().BoolVar(&includeExamples, "examples", false, "include examples")
	return cmd
}

func newShareCommand() *cobra.Command {
	var (
		outputDir string
		domain    string
		jsonOut   bool
	)
	cmd := &cobra.Command{
		Use:   "share BUNDLE|DOMAIN",
		Short: "Export safe derived artifacts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := report.Share(report.ShareOptions{BundleOrDomain: args[0], OutputDir: outputDir, Domain: domain})
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "shared artifacts -> %s\n", result.OutputDir)
			for _, file := range result.Files {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", file)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "output path")
	cmd.Flags().StringVar(&domain, "domain", "", "domain override")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

func findLatestBundle(domain string) (string, error) {
	safe := strings.NewReplacer(".", "-", "/", "-").Replace(domain)
	pattern := filepath.Join(capture.CapturesDir(), safe+"_*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	var dirs []string
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil && info.IsDir() {
			dirs = append(dirs, match)
		}
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("no captures found for %s; run recon first or pass --input", domain)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	return dirs[0], nil
}

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, value := range values {
		key, val, ok := strings.Cut(value, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header %q: expected key:value", value)
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return out, nil
}

func normalizeTarget(raw string) (domain string, launchURL string) {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
		domain = strings.Split(trimmed, "/")[0]
		return domain, raw
	}
	return raw, "https://" + raw
}

func summarizeEndpoints(flows []model.CapturedFlow, limit int) []output.EndpointSummary {
	counts := map[string]int{}
	for _, flow := range flows {
		key := strings.ToUpper(flow.Method) + " " + model.NormalizePath(flow.Path)
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] == counts[keys[j]] {
			return keys[i] < keys[j]
		}
		return counts[keys[i]] > counts[keys[j]]
	})
	if len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]output.EndpointSummary, 0, len(keys))
	for _, key := range keys {
		method, path, _ := strings.Cut(key, " ")
		out = append(out, output.EndpointSummary{Method: method, Path: path, Count: counts[key]})
	}
	return out
}

func writeJSON(w io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func writeReplaySummary(w io.Writer, summary replay.Summary) error {
	if summary.Mode == "dry_run" {
		fmt.Fprintf(w, "dry run: %d safe, %d unsafe, %d total\n", summary.Summary["safe"], summary.Summary["unsafe"], summary.Summary["total"])
		for _, endpoint := range summary.Endpoints {
			fmt.Fprintln(w, endpoint)
		}
		return nil
	}
	total := 0
	for _, count := range summary.Summary {
		total += count
	}
	fmt.Fprintf(w, "replayed %d flows", total)
	if summary.Domain != "" {
		fmt.Fprintf(w, " for %s", summary.Domain)
	}
	fmt.Fprintln(w)
	for _, category := range []string{"match", "drift", "auth_expired", "blocked", "error"} {
		if count := summary.Summary[category]; count > 0 {
			fmt.Fprintf(w, "%s: %d\n", category, count)
		}
	}
	for _, result := range summary.Results {
		fmt.Fprintf(w, "%s %s -> %s", result.Method, result.Path, result.Category)
		if result.ReplayedStatus != 0 {
			fmt.Fprintf(w, " (%d -> %d)", result.OriginalStatus, result.ReplayedStatus)
		}
		if result.Error != "" {
			fmt.Fprintf(w, ": %s", result.Error)
		}
		fmt.Fprintln(w)
	}
	return nil
}

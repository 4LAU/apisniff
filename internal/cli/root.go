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
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

func Execute() error {
	root := newRootCommand()
	return root.Execute()
}

var captureRun = capture.Capture

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
		jsonOutput      bool
		proxyURL        string
		headers         headerFlags
		cookie          string
		insecure        bool
		impersonate     string
		rateRequests    int
		rateConcurrency int
	)
	cmd := &cobra.Command{
		Use:   "probe [URL | rate URL]",
		Short: "Defense preflight",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && args[0] != "rate" {
				return nil
			}
			if len(args) == 2 && args[0] == "rate" {
				return nil
			}
			if len(args) == 1 && args[0] == "rate" {
				return errors.New("probe rate requires a URL argument")
			}
			return errors.New("usage: apisniff probe URL or apisniff probe rate URL")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			rateMode := args[0] == "rate"
			target := args[0]
			if rateMode {
				target = args[1]
			}
			parsedHeaders, err := parseHeaders(headers)
			if err != nil {
				return err
			}
			probeOptions := probe.Options{
				Proxy:       proxyURL,
				Headers:     parsedHeaders,
				Cookie:      cookie,
				Insecure:    insecure,
				Impersonate: impersonate,
				Timeout:     15 * time.Second,
			}
			var assessment *model.ProbeAssessment
			if rateMode {
				assessment, err = probe.RunRate(cmd.Context(), target, probeOptions, probe.RateOptions{
					Requests:    rateRequests,
					Concurrency: rateConcurrency,
				})
			} else {
				assessment, err = probe.Run(cmd.Context(), target, probeOptions)
			}
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), probeToJSON(assessment))
			}
			return output.WriteProbe(humanOutputConfig(cmd), assessment)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "route probes through proxy")
	cmd.Flags().VarP(&headers, "header", "H", "extra header (key:value)")
	cmd.Flags().StringVar(&cookie, "cookie", "", "Cookie header value")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification")
	cmd.Flags().StringVar(&impersonate, "impersonate", "chrome", "TLS profile")
	cmd.Flags().IntVar(&rateRequests, "rate-requests", 20, "requests to send for probe rate")
	cmd.Flags().IntVar(&rateConcurrency, "rate-concurrency", 1, "concurrency for probe rate")
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
			result, err := captureRun(cmd.Context(), capture.Config{
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
			return output.WriteRecon(humanOutputConfig(cmd), output.ReconResult{
				Domain:     result.Stats.Domain,
				BundleDir:  result.BundleDir,
				FlowsPath:  result.FlowsPath,
				KeptFlows:  result.Stats.KeptFlows,
				TotalFlows: result.Stats.TotalFlows,
			})
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
			if fetchGraphQL && outputDir == "" {
				return errors.New("--fetch-graphql requires --output-dir to store the introspection result")
			}
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
			if outputDir != "" {
				session := model.SessionStats{
					Domain:     domain,
					StartedAt:  time.Now().UTC().Format(time.RFC3339),
					TotalFlows: len(flows),
					KeptFlows:  len(flows),
					Dropped:    map[string]int{},
				}
				if err := report.WriteBundle(outputDir, flows, session); err != nil {
					return err
				}
				if fetchGraphQL {
					graphQL, err := report.FetchGraphQLSchemas(cmd.Context(), flows)
					if err != nil {
						return err
					}
					if err := report.WriteGraphQLResults(outputDir, graphQL); err != nil {
						return err
					}
				}
				result.BundleDir = outputDir
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}
			return output.WriteAnalyze(humanOutputConfig(cmd), result)
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
		forwardAuth   bool
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
				ForwardAuth:    forwardAuth,
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
			return output.WriteReplay(humanOutputConfig(cmd), summary)
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
	cmd.Flags().BoolVar(&forwardAuth, "forward-auth", false, "forward auth headers captured in flows")
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
			inclusions := spec.InclusionOptions{
				IncludeThirdParty: includeThirdParty,
				IncludeCategories: includeCategory,
				IncludeHosts:      includeHost,
			}
			if inclusionOptionsEnabled(inclusions) && isPrefilteredBundleInput(path) {
				fmt.Fprintln(cmd.ErrOrStderr(), "inclusion filters have no effect on pre-filtered bundles; pass the original capture file via --input")
			}
			specFlows := flows
			surface := spec.BuildSurfaceInventory(flows, domain)
			if inclusionOptionsEnabled(inclusions) {
				var err error
				specFlows, surface, err = spec.ApplyInclusionFilters(flows, domain, inclusions)
				if err != nil {
					return err
				}
			}
			if surfaceOutput != "" {
				if err := writeJSONFile(surfaceOutput, surface); err != nil {
					return err
				}
			}
			apiFlows := spec.FilterAPIFlows(specFlows)
			doc := spec.Generate(apiFlows, domain, auth.Detect(specFlows), spec.Options{
				InferSchemes:    inferSchemes,
				IncludeExamples: includeExamples,
			})
			data, err := spec.Marshal(doc, format)
			if err != nil {
				return err
			}
			if outputFile != "" {
				if err := os.WriteFile(outputFile, data, 0o600); err != nil {
					return err
				}
				paths, operations := countOpenAPIOperations(doc)
				return output.WriteSpecStatus(humanOutputConfig(cmd), output.SpecStatusResult{
					Domain:            domain,
					Format:            format,
					OutputPath:        outputFile,
					SurfaceOutputPath: surfaceOutput,
					Paths:             paths,
					Operations:        operations,
				})
			}
			if _, err := cmd.OutOrStdout().Write(append(data, '\n')); err != nil {
				return err
			}
			paths, operations := countOpenAPIOperations(doc)
			return output.WriteSpecStatus(humanOutputConfig(cmd), output.SpecStatusResult{
				Domain:            domain,
				Format:            format,
				SurfaceOutputPath: surfaceOutput,
				Paths:             paths,
				Operations:        operations,
			})
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
			return output.WriteShare(humanOutputConfig(cmd), output.ShareResult{
				OutputDir: result.OutputDir,
				Files:     result.Files,
			})
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

func humanOutputConfig(cmd *cobra.Command) output.Config {
	return output.Config{
		Color:  useColor(cmd.ErrOrStderr()),
		Width:  terminalWidth(cmd.ErrOrStderr()),
		Writer: cmd.ErrOrStderr(),
	}
}

func terminalWidth(w io.Writer) int {
	file, ok := w.(*os.File)
	if !ok {
		return 80
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return 80
	}
	width, _, err := term.GetSize(file.Fd())
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func writeJSON(w io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

type probeJSON struct {
	SchemaVersion  int                    `json:"schema_version"`
	URL            string                 `json:"url"`
	Verdict        string                 `json:"verdict"`
	Recommendation string                 `json:"recommendation"`
	Probes         []probeResultJSON      `json:"probes"`
	Vendors        []model.VendorMatch    `json:"vendors"`
	GraphQL        *model.GraphQLResult   `json:"graphql,omitempty"`
	RateLimit      *model.RateLimitResult `json:"rate_limit,omitempty"`
}

type probeResultJSON struct {
	Variant   string  `json:"variant"`
	Status    int     `json:"status,omitempty"`
	ElapsedMS float64 `json:"elapsed_ms"`
	Blocked   bool    `json:"blocked"`
	Challenge bool    `json:"challenge"`
	Error     string  `json:"error,omitempty"`
}

func probeToJSON(assessment *model.ProbeAssessment) probeJSON {
	if assessment == nil {
		return probeJSON{SchemaVersion: 1}
	}
	probes := make([]probeResultJSON, 0, len(assessment.Results))
	for _, result := range assessment.Results {
		probes = append(probes, probeResultJSON{
			Variant:   result.Variant,
			Status:    result.Status,
			ElapsedMS: result.ElapsedMS(),
			Blocked:   result.IsBlocked(),
			Challenge: result.IsChallenge(),
			Error:     result.Error,
		})
	}
	return probeJSON{
		SchemaVersion:  1,
		URL:            assessment.URL,
		Verdict:        assessment.Verdict.String(),
		Recommendation: assessment.Recommendation,
		Probes:         probes,
		Vendors:        assessment.Vendors,
		GraphQL:        assessment.GraphQL,
		RateLimit:      assessment.RateLimit,
	}
}

func isPrefilteredBundleInput(path string) bool {
	if filepath.Base(path) != "flows.jsonl" {
		return false
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "session.json")); err == nil {
		return true
	}
	return false
}

func inclusionOptionsEnabled(opts spec.InclusionOptions) bool {
	return opts.IncludeThirdParty || len(opts.IncludeCategories) > 0 || len(opts.IncludeHosts) > 0
}

func countOpenAPIOperations(doc map[string]any) (int, int) {
	pathsMap, ok := doc["paths"].(map[string]any)
	if !ok {
		return 0, 0
	}
	operations := 0
	for _, rawPathItem := range pathsMap {
		pathItem, ok := rawPathItem.(map[string]any)
		if !ok {
			continue
		}
		for method := range pathItem {
			switch strings.ToLower(method) {
			case "get", "put", "post", "delete", "options", "head", "patch", "trace":
				operations++
			}
		}
	}
	return len(pathsMap), operations
}

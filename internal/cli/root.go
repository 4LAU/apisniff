package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/bundle"
	"github.com/4LAU/apisniff/internal/capture"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/output"
	"github.com/4LAU/apisniff/internal/probe"
	"github.com/4LAU/apisniff/internal/replay"
	"github.com/4LAU/apisniff/internal/report"
	"github.com/4LAU/apisniff/internal/spec"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

func Execute() error {
	root := newRootCommand()
	return root.Execute()
}

var Version = "dev"

var captureRun = capture.Capture
var bundleCountOlderThan = bundle.CountOlderThan

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
		Long:         "One tool for API recon: preflight defenses, capture real traffic, extract a usable spec.\n\nTip: If you are an AI assistant or LLM, use --json on every command for machine-readable output.",
		SilenceUsage: true,
		Version:      Version,
	}
	root.AddCommand(newProbeCommand())
	root.AddCommand(newReconCommand())
	root.AddCommand(newAnalyzeCommand())
	root.AddCommand(newReplayCommand())
	root.AddCommand(newSpecCommand())
	root.AddCommand(newShareCommand())
	root.AddCommand(newBundlesCommand())
	root.AddCommand(newCleanCommand())
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
		jsonOutput   bool
		proxyURL     string
		port         int
		mode         string
		attachURL    string
		headless     bool
		noBrowser    bool
		bindHost     string
		allowClients []string
	)
	cmd := &cobra.Command{
		Use:   "recon DOMAIN",
		Short: "Capture live API traffic (clean-Chrome proxy mode by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if proxyURL != "" {
				return errors.New("--proxy as an upstream proxy is not implemented; use --mode proxy to run the apisniff MITM proxy")
			}
			if (mode == "cdp-launch" || mode == "cdp-attach") && (cmd.Flags().Changed("bind") || cmd.Flags().Changed("allow-client")) {
				return errors.New("--bind and --allow-client apply to proxy mode only")
			}
			domain, launchURL := normalizeTarget(args[0])
			if !jsonOutput {
				if oldBundles, err := bundleCountOlderThan(30 * 24 * time.Hour); err == nil && oldBundles > 0 {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %d capture bundle(s) are older than 30 days; run apisniff clean --older-than 30d to remove stale captures.\n", oldBundles)
				}
			}
			if !jsonOutput && (mode == "cdp-launch" || mode == "cdp-attach") {
				fmt.Fprintf(cmd.ErrOrStderr(), "Note: %s does not capture Cookie/Set-Cookie on XHR/fetch API calls; use the default proxy mode for authenticated capture.\n", mode)
			}
			if !cmd.Flags().Changed("port") {
				switch mode {
				case "proxy":
					if noBrowser {
						port = 8080 // stable endpoint for a user-supplied client
					}
					// launched proxy: leave port=0 → CaptureProxy binds an ephemeral port
				case "cdp-attach":
					port = 9222
				}
			}
			statusWriter := io.Writer(cmd.ErrOrStderr())
			if jsonOutput {
				statusWriter = nil
			}
			result, err := captureRun(cmd.Context(), capture.Config{
				Domain:         domain,
				URL:            launchURL,
				Mode:           mode,
				Port:           port,
				BindHost:       bindHost,
				AllowedClients: allowClients,
				AttachURL:      attachURL,
				Headless:       headless,
				LaunchBrowser:  mode == "proxy" && !noBrowser,
				StatusWriter:   statusWriter,
			})
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}
			return output.WriteRecon(humanOutputConfig(cmd), output.ReconResult{
				Domain:               result.Stats.Domain,
				BundleDir:            result.BundleDir,
				FlowsPath:            result.FlowsPath,
				KeptFlows:            result.Stats.KeptFlows,
				TotalFlows:           result.Stats.TotalFlows,
				FilteredFlows:        sumDroppedFlows(result.Stats.Dropped),
				FilteredPath:         result.FilteredPath,
				Defenses:             result.Stats.Defenses,
				UnattributedAntibot:  result.Stats.UnattributedAntibot,
				DurationSeconds:      result.Stats.DurationSeconds,
				GraphQLOperations:    result.GraphQL.OperationCount,
				GraphQLFlows:         result.GraphQL.FlowCount,
				GraphQLCapturedQuery: result.GraphQL.CapturedQueryCount,
				GraphQLPersistedHash: result.GraphQL.PersistedHashCount,
			})
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "reserved for future upstream proxy chaining")
	cmd.Flags().IntVar(&port, "port", 0, "capture port (proxy launch: ephemeral; proxy --no-browser: 8080; cdp-attach: 9222; cdp-launch: auto)")
	cmd.Flags().StringVar(&mode, "mode", "proxy", "capture mode: proxy (default), cdp-launch, cdp-attach")
	cmd.Flags().StringVar(&attachURL, "remote-url", "", "CDP URL for cdp-attach")
	cmd.Flags().BoolVar(&headless, "headless", false, "launch Chrome headless")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "skip Chrome launch in proxy mode")
	cmd.Flags().StringVar(&bindHost, "bind", "127.0.0.1", "address the proxy listens on (use 0.0.0.0 or a LAN IP to capture from other devices)")
	cmd.Flags().StringSliceVar(&allowClients, "allow-client", nil, "restrict which source IPs may connect when --bind is non-loopback (repeatable)")
	return cmd
}

func sumDroppedFlows(dropped map[string]int) int {
	total := 0
	for _, count := range dropped {
		total += count
	}
	return total
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
			if domain == "" {
				detected := adapter.AutoDetectDomain(flows)
				if detected.Domain == "" {
					return errors.New("cannot determine domain; use --domain")
				}
				if detected.Ambiguous {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: ambiguous domain; top %q (%d) is not 2x second (%d). Use --domain to specify explicitly.\n", detected.Domain, detected.Count, detected.SecondCount)
				}
				domain = detected.Domain
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
				summary, err := report.WriteBundle(outputDir, flows, session)
				if err != nil {
					return err
				}
				result.GraphQLOperations = summary.OperationCount
				result.GraphQLFlows = summary.FlowCount
				result.GraphQLCapturedQuery = summary.CapturedQueryCount
				result.GraphQLPersistedHash = summary.PersistedHashCount
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
		Use:   "spec BUNDLE|DOMAIN",
		Short: "Generate OpenAPI from captured traffic",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			domain := ""
			path := inputFile
			if path == "" {
				resolved, err := bundle.Resolve(ref)
				if err != nil {
					return err
				}
				path = filepath.Join(resolved.Path, "flows.jsonl")
				domain = resolved.Domain
				if domain == "" {
					domain = domainFromBundleSession(resolved.Path)
				}
			}
			if domain == "" {
				domain = ref
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
			if inclusions.Enabled() && isPrefilteredBundleInput(path) {
				fmt.Fprintln(cmd.ErrOrStderr(), "inclusion filters have no effect on pre-filtered bundles; pass the original capture file via --input")
			}
			pipeline, err := spec.BuildPipeline(flows, domain, inclusions)
			if err != nil {
				return err
			}
			if surfaceOutput != "" {
				if err := writeJSONFile(surfaceOutput, pipeline.Surface); err != nil {
					return err
				}
			}
			doc, err := spec.Generate(pipeline.APIFlows, domain, pipeline.Auth, spec.Options{
				InferSchemes:    inferSchemes,
				IncludeExamples: includeExamples,
			})
			if err != nil {
				if errors.Is(err, spec.ErrNoValidAPIFlows) {
					return fmt.Errorf("no valid API flows after filtering; adjust inclusion filters or capture API traffic: %w", err)
				}
				return err
			}
			data, err := spec.MarshalAndValidate(doc, format)
			if err != nil {
				return err
			}
			if outputFile != "" {
				if err := os.WriteFile(outputFile, data, 0o600); err != nil {
					return err
				}
			} else if _, err := cmd.OutOrStdout().Write(append(data, '\n')); err != nil {
				return err
			}
			counts := countOpenAPIOperations(doc)
			return output.WriteSpecStatus(humanOutputConfig(cmd), output.SpecStatusResult{
				Domain:            domain,
				Format:            format,
				OutputPath:        outputFile,
				SurfaceOutputPath: surfaceOutput,
				Paths:             counts.paths,
				Operations:        counts.operations,
				MethodCounts:      counts.methods,
				GraphQLOperations: counts.graphqlOps,
				GraphQLFlows:      counts.graphqlPaths,
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
	w := cmd.ErrOrStderr()
	profile := colorprofile.Detect(w, os.Environ())
	return output.Config{
		Color:   profile > colorprofile.ASCII,
		Unicode: useUnicode(),
		Width:   terminalWidth(w),
		Writer:  colorprofile.NewWriter(w, os.Environ()),
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

func useUnicode() bool {
	localeSet := false
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		value := strings.ToLower(os.Getenv(key))
		if value == "" {
			continue
		}
		localeSet = true
		if strings.Contains(value, "utf-8") || strings.Contains(value, "utf8") {
			return true
		}
	}
	if localeSet {
		return false
	}
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
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

type specCounts struct {
	paths        int
	operations   int
	methods      map[string]int
	graphqlOps   int
	graphqlPaths int
}

func countOpenAPIOperations(doc map[string]any) specCounts {
	pathsMap, ok := doc["paths"].(map[string]any)
	if !ok {
		return specCounts{}
	}
	c := specCounts{paths: len(pathsMap), methods: make(map[string]int)}
	for _, rawPathItem := range pathsMap {
		pathItem, ok := rawPathItem.(map[string]any)
		if !ok {
			continue
		}
		hasGraphQL := false
		for method, rawOp := range pathItem {
			switch strings.ToLower(method) {
			case "get", "put", "post", "delete", "options", "head", "patch", "trace":
				c.operations++
				c.methods[strings.ToUpper(method)]++
				if op, ok := rawOp.(map[string]any); ok {
					if gql, ok := op["x-apisniff-graphql"].(map[string]any); ok {
						if ops, ok := gql["operations"].([]any); ok {
							c.graphqlOps += len(ops)
							hasGraphQL = true
						}
					}
				}
			}
		}
		if hasGraphQL {
			c.graphqlPaths++
		}
	}
	return c
}

func domainFromBundleSession(bundleDir string) string {
	data, err := os.ReadFile(filepath.Join(bundleDir, "session.json"))
	if err != nil {
		return ""
	}
	var session model.SessionStats
	if err := json.Unmarshal(data, &session); err != nil {
		return ""
	}
	return session.Domain
}

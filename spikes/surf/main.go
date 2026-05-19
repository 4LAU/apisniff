package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/enetx/surf"
)

const (
	defaultEchoURL = "https://tls.peet.ws/api/all"
	defaultTargets = "https://www.cloudflare.com," +
		"https://www.akamai.com," +
		"https://datadome.co"
	maxProbeBodyBytes = 1 << 20
)

type report struct {
	GeneratedAt        time.Time          `json:"generated_at"`
	SurfProfile        string             `json:"surf_profile"`
	Echo               echoProbe          `json:"echo"`
	Targets            []targetProbe      `json:"targets"`
	ExpectedComparison expectedComparison `json:"expected_comparison"`
	BaselineComparison baselineComparison `json:"baseline_comparison"`
}

type echoProbe struct {
	URL             string              `json:"url"`
	Status          int                 `json:"status,omitempty"`
	Protocol        string              `json:"protocol,omitempty"`
	Elapsed         string              `json:"elapsed,omitempty"`
	Error           string              `json:"error,omitempty"`
	HTTPVersion     string              `json:"http_version,omitempty"`
	UserAgent       string              `json:"user_agent,omitempty"`
	TLS             tlsFingerprint      `json:"tls"`
	PQKeyShare      pqKeyShare          `json:"pq_key_share"`
	ParseWarnings   []string            `json:"parse_warnings,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
}

type tlsFingerprint struct {
	JA3Hash         string   `json:"ja3_hash,omitempty"`
	JA4             string   `json:"ja4,omitempty"`
	JA3             string   `json:"ja3,omitempty"`
	SupportedGroups []string `json:"supported_groups,omitempty"`
	KeyShares       []string `json:"key_shares,omitempty"`
}

type pqKeyShare struct {
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

type targetProbe struct {
	URL             string              `json:"url"`
	Status          int                 `json:"status,omitempty"`
	Protocol        string              `json:"protocol,omitempty"`
	Elapsed         string              `json:"elapsed,omitempty"`
	Error           string              `json:"error,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	Blocked         bool                `json:"blocked"`
	ChallengeSignal []string            `json:"challenge_signal,omitempty"`
}

type expectedComparison struct {
	KnownJA3Hash string           `json:"known_ja3_hash,omitempty"`
	KnownJA4     string           `json:"known_ja4,omitempty"`
	JA3Hash      comparisonResult `json:"ja3_hash"`
	JA4          comparisonResult `json:"ja4"`
}

type comparisonResult struct {
	Status   string `json:"status"`
	Actual   string `json:"actual,omitempty"`
	Expected string `json:"expected,omitempty"`
}

type baselineComparison struct {
	Status string                   `json:"status"`
	Notes  []string                 `json:"notes,omitempty"`
	Tools  []baselineToolComparison `json:"tools,omitempty"`
}

type baselineToolComparison struct {
	Tool    string                     `json:"tool"`
	Results []baselineTargetComparison `json:"results"`
}

type baselineTargetComparison struct {
	URL             string `json:"url"`
	Status          string `json:"status"`
	SurfStatus      int    `json:"surf_status,omitempty"`
	BaselineStatus  int    `json:"baseline_status,omitempty"`
	SurfBlocked     bool   `json:"surf_blocked"`
	BaselineBlocked bool   `json:"baseline_blocked"`
}

type baselineProbe struct {
	URL     string
	Status  int
	Blocked bool
}

func main() {
	echoURL := flag.String("echo", defaultEchoURL, "TLS fingerprint echo URL")
	targetsFlag := flag.String("targets", defaultTargets, "comma-separated target URLs to probe")
	timeoutFlag := flag.Duration("timeout", 20*time.Second, "per-request timeout")
	outputPath := flag.String("output", "", "write JSON report to this path instead of stdout")
	knownJA3Hash := flag.String("known-ja3-hash", "", "known Chrome 145 JA3 hash to compare against")
	knownJA4 := flag.String("known-ja4", "", "known Chrome 145 JA4 value to compare against")
	baselinePath := flag.String("baseline", "", "optional curl-cffi/Impit baseline JSON to compare pass/block results")
	flag.Parse()

	client := surf.NewClient().
		Builder().
		Impersonate().
		Chrome().
		Timeout(*timeoutFlag).
		Build().
		Unwrap()
	defer client.CloseIdleConnections()

	httpClient := client.Std()

	out := report{
		GeneratedAt: time.Now().UTC(),
		SurfProfile: "Surf Impersonate().Chrome() / Chrome 145",
		Echo:        probeEcho(context.Background(), httpClient, *echoURL, *timeoutFlag),
	}

	out.ExpectedComparison = compareExpected(out.Echo.TLS, *knownJA3Hash, *knownJA4)

	for _, target := range parseCSV(*targetsFlag) {
		out.Targets = append(out.Targets, probeTarget(context.Background(), httpClient, target, *timeoutFlag))
	}

	out.BaselineComparison = compareBaselines(*baselinePath, out.Targets)

	if err := writeJSON(*outputPath, out); err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		os.Exit(1)
	}
}

func probeEcho(parent context.Context, client *http.Client, rawURL string, timeout time.Duration) echoProbe {
	start := time.Now()
	resp, body, err := doGET(parent, client, rawURL, timeout, 4*maxProbeBodyBytes)
	probe := echoProbe{URL: rawURL, Elapsed: time.Since(start).String()}
	if err != nil {
		probe.Error = err.Error()
		probe.PQKeyShare = pqKeyShare{
			Status: "inconclusive",
			Reason: "echo request failed",
		}
		return probe
	}

	probe.Status = resp.StatusCode
	probe.Protocol = resp.Proto
	probe.ResponseHeaders = filterInterestingHeaders(resp.Header)

	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		probe.Error = "decode echo JSON: " + err.Error()
		probe.PQKeyShare = pqKeyShare{
			Status: "inconclusive",
			Reason: "echo response was not JSON",
		}
		return probe
	}

	probe.HTTPVersion = firstString(payload,
		[]string{"http_version"},
		[]string{"http", "version"},
		[]string{"http2", "akamai_fingerprint"},
	)
	probe.UserAgent = firstString(payload,
		[]string{"user_agent"},
		[]string{"headers", "user-agent"},
		[]string{"http", "user_agent"},
	)
	probe.TLS = extractTLS(payload)
	probe.PQKeyShare = detectPQKeyShare(probe.TLS, payload)

	if probe.TLS.JA3Hash == "" {
		probe.ParseWarnings = append(probe.ParseWarnings, "tls.ja3_hash not found")
	}
	if probe.TLS.JA4 == "" {
		probe.ParseWarnings = append(probe.ParseWarnings, "tls.ja4 not found")
	}
	if len(probe.TLS.KeyShares) == 0 {
		probe.ParseWarnings = append(probe.ParseWarnings, "key_share/shared_keys not found")
	}

	return probe
}

func probeTarget(parent context.Context, client *http.Client, rawURL string, timeout time.Duration) targetProbe {
	start := time.Now()
	resp, body, err := doGET(parent, client, rawURL, timeout, maxProbeBodyBytes)
	probe := targetProbe{URL: rawURL, Elapsed: time.Since(start).String()}
	if err != nil {
		probe.Error = err.Error()
		probe.Blocked = true
		probe.ChallengeSignal = []string{"request_error"}
		return probe
	}

	probe.Status = resp.StatusCode
	probe.Protocol = resp.Proto
	probe.Headers = filterInterestingHeaders(resp.Header)
	probe.Blocked, probe.ChallengeSignal = detectChallenge(resp.StatusCode, resp.Header, body)
	return probe
}

func doGET(parent context.Context, client *http.Client, rawURL string, timeout time.Duration, limit int64) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit))
	if readErr != nil {
		return resp, body, readErr
	}

	return resp, body, nil
}

func extractTLS(root any) tlsFingerprint {
	tlsRoot := valueAt(root, []string{"tls"})
	if tlsRoot == nil {
		tlsRoot = root
	}

	return tlsFingerprint{
		JA3Hash: firstString(root, []string{"tls", "ja3_hash"}, []string{"ja3_hash"}),
		JA4:     firstString(root, []string{"tls", "ja4"}, []string{"ja4"}),
		JA3:     firstString(root, []string{"tls", "ja3"}, []string{"ja3"}),
		SupportedGroups: uniqueStrings(flattenValues(collectByKey(tlsRoot, func(key string) bool {
			key = normalizeKey(key)
			return key == "supportedgroups" || key == "groups" || strings.Contains(key, "supportedgroup")
		}))),
		KeyShares: uniqueStrings(flattenValues(collectByKey(tlsRoot, func(key string) bool {
			key = normalizeKey(key)
			return key == "keyshare" ||
				key == "keyshares" ||
				key == "sharedkeys" ||
				strings.Contains(key, "keyshare") ||
				strings.Contains(key, "sharedkey")
		}))),
	}
}

func detectPQKeyShare(tls tlsFingerprint, root any) pqKeyShare {
	var searchSpace []string
	searchSpace = append(searchSpace, tls.KeyShares...)
	searchSpace = append(searchSpace, tls.SupportedGroups...)

	evidence := findPQEvidence(searchSpace)
	if len(evidence) > 0 {
		return pqKeyShare{Status: "present", Evidence: evidence}
	}

	extensionStrings := flattenValues(collectByKey(root, func(key string) bool {
		key = normalizeKey(key)
		return strings.Contains(key, "extension") ||
			strings.Contains(key, "keyshare") ||
			strings.Contains(key, "sharedkey") ||
			strings.Contains(key, "supportedgroup")
	}))

	evidence = findPQEvidence(extensionStrings)
	if len(evidence) > 0 {
		return pqKeyShare{Status: "present", Evidence: evidence}
	}

	if len(tls.KeyShares) > 0 || len(extensionStrings) > 0 {
		return pqKeyShare{
			Status: "absent",
			Reason: "echo schema exposed TLS key share/group data but no X25519MLKEM768 marker was found",
		}
	}

	return pqKeyShare{
		Status: "inconclusive",
		Reason: "echo schema did not expose key_share/shared_keys details",
	}
}

func findPQEvidence(values []string) []string {
	markers := []string{
		"x25519mlkem768",
		"x25519-mlkem768",
		"x25519_mlkem768",
		"x25519kyber768",
		"x25519-kyber768",
		"mlkem",
		"ml-kem",
		"kyber",
		"4588",
		"0x11ec",
	}

	var evidence []string
	for _, value := range values {
		lower := strings.ToLower(value)
		for _, marker := range markers {
			if strings.Contains(lower, marker) {
				evidence = append(evidence, value)
				break
			}
		}
	}

	return uniqueStrings(evidence)
}

func detectChallenge(status int, headers http.Header, body []byte) (bool, []string) {
	var signals []string

	switch status {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		signals = append(signals, fmt.Sprintf("status_%d", status))
	}

	for name, values := range headers {
		lowerName := strings.ToLower(name)
		joined := strings.ToLower(strings.Join(values, " "))

		switch {
		case strings.HasPrefix(lowerName, "cf-"):
			if lowerName == "cf-mitigated" || strings.Contains(joined, "challenge") {
				signals = append(signals, lowerName)
			}
		case strings.Contains(lowerName, "akamai"):
			signals = append(signals, lowerName)
		case strings.Contains(lowerName, "datadome"):
			signals = append(signals, lowerName)
		case lowerName == "set-cookie":
			if strings.Contains(joined, "datadome") ||
				strings.Contains(joined, "_abck") ||
				strings.Contains(joined, "bm_sz") ||
				strings.Contains(joined, "ak_bmsc") {
				signals = append(signals, "bot_cookie")
			}
		}
	}

	bodySignals := map[string]string{
		"cf-chl":                "cloudflare_challenge",
		"just a moment":         "cloudflare_challenge",
		"checking your browser": "browser_check",
		"attention required":    "browser_check",
		"challenge-platform":    "challenge_platform",
		"akamai bot manager":    "akamai_bot_manager",
		"datadome":              "datadome",
		"captcha":               "captcha",
		"px-captcha":            "perimeterx",
		"access denied":         "access_denied",
	}

	lowerBody := strings.ToLower(string(body))
	for needle, signal := range bodySignals {
		if strings.Contains(lowerBody, needle) {
			signals = append(signals, signal)
		}
	}

	signals = uniqueStrings(signals)
	return len(signals) > 0, signals
}

func compareExpected(tls tlsFingerprint, knownJA3Hash, knownJA4 string) expectedComparison {
	return expectedComparison{
		KnownJA3Hash: knownJA3Hash,
		KnownJA4:     knownJA4,
		JA3Hash:      compareValue(tls.JA3Hash, knownJA3Hash),
		JA4:          compareValue(tls.JA4, knownJA4),
	}
}

func compareBaselines(path string, surfTargets []targetProbe) baselineComparison {
	if path == "" {
		return baselineComparison{
			Status: "not_run",
			Notes: []string{
				"This spike records Surf results only unless --baseline is provided.",
				"Run curl-cffi and Impit against the same targets and compare their blocked/challenge signals with --baseline.",
			},
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return baselineComparison{
			Status: "error",
			Notes:  []string{"open baseline JSON: " + err.Error()},
		}
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.UseNumber()

	var payload any
	if err := decoder.Decode(&payload); err != nil {
		return baselineComparison{
			Status: "error",
			Notes:  []string{"decode baseline JSON: " + err.Error()},
		}
	}

	tools := extractBaselineTools(payload)
	if len(tools) == 0 {
		return baselineComparison{
			Status: "empty",
			Notes:  []string{"baseline JSON did not contain probe rows with url/status/blocked fields"},
		}
	}

	surfByURL := make(map[string]targetProbe, len(surfTargets))
	for _, target := range surfTargets {
		surfByURL[target.URL] = target
	}

	comparison := baselineComparison{Status: "matched"}
	var mismatches int
	for _, tool := range tools {
		toolComparison := baselineToolComparison{Tool: tool.name}
		for _, baseline := range tool.probes {
			targetComparison := baselineTargetComparison{
				URL:             baseline.URL,
				BaselineStatus:  baseline.Status,
				BaselineBlocked: baseline.Blocked,
			}

			surfTarget, ok := surfByURL[baseline.URL]
			if !ok {
				targetComparison.Status = "surf_missing"
				mismatches++
				toolComparison.Results = append(toolComparison.Results, targetComparison)
				continue
			}

			targetComparison.SurfStatus = surfTarget.Status
			targetComparison.SurfBlocked = surfTarget.Blocked
			if surfTarget.Blocked == baseline.Blocked {
				targetComparison.Status = "match"
			} else {
				targetComparison.Status = "mismatch"
				mismatches++
			}

			toolComparison.Results = append(toolComparison.Results, targetComparison)
		}
		comparison.Tools = append(comparison.Tools, toolComparison)
	}

	if mismatches > 0 {
		comparison.Status = "mismatch"
	}

	return comparison
}

type baselineTool struct {
	name   string
	probes []baselineProbe
}

func extractBaselineTools(payload any) []baselineTool {
	if probes := decodeBaselineProbeList(payload); len(probes) > 0 {
		return []baselineTool{{name: "baseline", probes: probes}}
	}

	obj, ok := payload.(map[string]any)
	if !ok {
		return nil
	}

	var tools []baselineTool
	for name, value := range obj {
		probes := decodeBaselineProbeList(value)
		if len(probes) == 0 {
			probes = decodeBaselineProbeList(valueAt(value, []string{"targets"}))
		}
		if len(probes) == 0 {
			probes = decodeBaselineProbeList(valueAt(value, []string{"results"}))
		}
		if len(probes) == 0 {
			continue
		}

		tools = append(tools, baselineTool{name: name, probes: probes})
	}

	sort.Slice(tools, func(i, j int) bool {
		return tools[i].name < tools[j].name
	})

	return tools
}

func decodeBaselineProbeList(value any) []baselineProbe {
	rows, ok := value.([]any)
	if !ok {
		return nil
	}

	var probes []baselineProbe
	for _, row := range rows {
		obj, ok := row.(map[string]any)
		if !ok {
			continue
		}

		url := firstString(obj, []string{"url"})
		if url == "" {
			continue
		}

		status := intAt(obj, []string{"status"}, []string{"status_code"})
		blocked, ok := boolAt(obj, []string{"blocked"}, []string{"challenged"}, []string{"challenge"})
		if !ok {
			blocked, _ = statusIndicatesBlock(status)
		}

		probes = append(probes, baselineProbe{
			URL:     url,
			Status:  status,
			Blocked: blocked,
		})
	}

	return probes
}

func intAt(root any, paths ...[]string) int {
	for _, path := range paths {
		value := valueAt(root, path)
		switch typed := value.(type) {
		case int:
			return typed
		case float64:
			return int(typed)
		case json.Number:
			parsed, err := typed.Int64()
			if err == nil {
				return int(parsed)
			}
		}
	}

	return 0
}

func boolAt(root any, paths ...[]string) (bool, bool) {
	for _, path := range paths {
		value := valueAt(root, path)
		switch typed := value.(type) {
		case bool:
			return typed, true
		case string:
			switch strings.ToLower(strings.TrimSpace(typed)) {
			case "true", "yes", "blocked", "challenge", "challenged":
				return true, true
			case "false", "no", "passed", "pass":
				return false, true
			}
		}
	}

	return false, false
}

func statusIndicatesBlock(status int) (bool, bool) {
	switch status {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true, true
	case 0:
		return false, false
	default:
		return false, true
	}
}

func compareValue(actual, expected string) comparisonResult {
	result := comparisonResult{Actual: actual, Expected: expected}
	switch {
	case expected == "":
		result.Status = "not_configured"
	case actual == "":
		result.Status = "missing_actual"
	case actual == expected:
		result.Status = "match"
	default:
		result.Status = "mismatch"
	}

	return result
}

func firstString(root any, paths ...[]string) string {
	for _, path := range paths {
		if value := valueAt(root, path); value != nil {
			if str, ok := stringify(value); ok {
				return str
			}
		}
	}

	return ""
}

func valueAt(root any, path []string) any {
	current := root
	for _, part := range path {
		next, ok := childValue(current, part)
		if !ok {
			return nil
		}
		current = next
	}

	return current
}

func childValue(value any, key string) (any, bool) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}

	for currentKey, currentValue := range obj {
		if strings.EqualFold(currentKey, key) || normalizeKey(currentKey) == normalizeKey(key) {
			return currentValue, true
		}
	}

	return nil, false
}

func collectByKey(root any, match func(string) bool) []any {
	var values []any

	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if match(key) {
					values = append(values, child)
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}

	walk(root)
	return values
}

func flattenValues(values []any) []string {
	var out []string

	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case string:
			out = append(out, typed)
		case float64:
			out = append(out, fmt.Sprintf("%.0f", typed))
		case bool:
			out = append(out, fmt.Sprintf("%t", typed))
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case map[string]any:
			for key, child := range typed {
				if str, ok := stringify(child); ok {
					out = append(out, key+": "+str)
					continue
				}
				walk(child)
			}
		}
	}

	for _, value := range values {
		walk(value)
	}

	return out
}

func stringify(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, typed != ""
	case json.Number:
		return typed.String(), true
	case float64:
		return fmt.Sprintf("%.0f", typed), true
	case []any:
		var parts []string
		for _, item := range typed {
			if str, ok := stringify(item); ok {
				parts = append(parts, str)
			}
		}
		return strings.Join(parts, ", "), len(parts) > 0
	default:
		return "", false
	}
}

func normalizeKey(key string) string {
	var buf strings.Builder
	for _, r := range strings.ToLower(key) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			buf.WriteRune(r)
		}
	}

	return buf.String()
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}

	sort.Strings(out)
	return out
}

func filterInterestingHeaders(headers http.Header) map[string][]string {
	out := make(map[string][]string)

	for name, values := range headers {
		lower := strings.ToLower(name)
		if lower == "server" ||
			lower == "content-type" ||
			strings.HasPrefix(lower, "cf-") ||
			strings.Contains(lower, "akamai") ||
			strings.Contains(lower, "datadome") {
			out[name] = append([]string(nil), values...)
			continue
		}

		if lower == "set-cookie" {
			for _, value := range values {
				lowerValue := strings.ToLower(value)
				if strings.Contains(lowerValue, "datadome") ||
					strings.Contains(lowerValue, "_abck") ||
					strings.Contains(lowerValue, "bm_sz") ||
					strings.Contains(lowerValue, "ak_bmsc") {
					out[name] = append(out[name], value)
				}
			}
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func parseCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}

	return out
}

func writeJSON(path string, value any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return err
	}

	if path == "" || path == "-" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}

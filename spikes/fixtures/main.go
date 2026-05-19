package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	defaultFlowsPath    = "testdata/golden/phase0/classify/flows.jsonl"
	defaultExpectedPath = "testdata/golden/phase0/classify/expected.json"
)

type CapturedFlow struct {
	Method          string            `json:"method"`
	Host            string            `json:"host"`
	Path            string            `json:"path"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     *string           `json:"request_body"`
	ResponseStatus  int               `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    *string           `json:"response_body"`
	BodyEncoding    string            `json:"_body_encoding"`
	Tags            []string          `json:"tags"`
	Timestamp       float64           `json:"timestamp"`
}

type ClassifyResult struct {
	Action   string        `json:"action"`
	Category string        `json:"category"`
	Flow     *CapturedFlow `json:"flow"`
}

type stubDecision struct {
	action   string
	category string
	tags     []string
}

func main() {
	flowsPath := flag.String("flows", defaultFlowsPath, "path to captured flows JSONL fixture")
	expectedPath := flag.String("expected", defaultExpectedPath, "path to expected classification JSON fixture")
	flag.Parse()

	flows, err := loadFlows(*flowsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load flows: %v\n", err)
		os.Exit(2)
	}

	expected, err := loadExpected(*expectedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load expected: %v\n", err)
		os.Exit(2)
	}

	actual := classifyAll(flows)
	expectedJSON, err := normalizedJSON(expected)
	if err != nil {
		fmt.Fprintf(os.Stderr, "normalize expected: %v\n", err)
		os.Exit(2)
	}
	actualJSON, err := normalizedJSON(actual)
	if err != nil {
		fmt.Fprintf(os.Stderr, "normalize actual: %v\n", err)
		os.Exit(2)
	}

	if !bytes.Equal(expectedJSON, actualJSON) {
		fmt.Fprintln(os.Stderr, "golden fixture mismatch")
		fmt.Fprintln(os.Stderr, diffLines(string(expectedJSON), string(actualJSON)))
		os.Exit(1)
	}

	fmt.Printf("ok: %d classification results match %s\n", len(actual), *expectedPath)
}

func loadFlows(path string) ([]CapturedFlow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var flows []CapturedFlow
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var flow CapturedFlow
		if err := json.Unmarshal([]byte(line), &flow); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		flows = append(flows, flow)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return flows, nil
}

func loadExpected(path string) ([]ClassifyResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var expected []ClassifyResult
	if err := json.Unmarshal(data, &expected); err != nil {
		return nil, err
	}
	return expected, nil
}

func classifyAll(flows []CapturedFlow) []ClassifyResult {
	results := make([]ClassifyResult, 0, len(flows))
	for _, flow := range flows {
		results = append(results, classifyStub(flow))
	}
	return results
}

func classifyStub(flow CapturedFlow) ClassifyResult {
	decisions := map[string]stubDecision{
		"GET api.example.com /v1/users": {
			action:   "keep",
			category: "",
			tags:     []string{"api"},
		},
		"OPTIONS api.example.com /v1/users": {
			action:   "drop",
			category: "options",
		},
		"GET static.examplecdn.com /assets/app.js": {
			action:   "drop",
			category: "static_asset",
		},
	}

	key := flow.Method + " " + flow.Host + " " + flow.Path
	decision, ok := decisions[key]
	if !ok {
		return ClassifyResult{
			Action:   "drop",
			Category: "unclassified_stub",
			Flow:     nil,
		}
	}

	if decision.action == "drop" {
		return ClassifyResult{
			Action:   decision.action,
			Category: decision.category,
			Flow:     nil,
		}
	}

	kept := flow
	kept.Tags = append([]string(nil), decision.tags...)
	return ClassifyResult{
		Action:   decision.action,
		Category: decision.category,
		Flow:     &kept,
	}
}

func normalizedJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func diffLines(expected, actual string) string {
	expectedLines := strings.Split(strings.TrimSuffix(expected, "\n"), "\n")
	actualLines := strings.Split(strings.TrimSuffix(actual, "\n"), "\n")
	ops := shortestEditScript(expectedLines, actualLines)

	var b strings.Builder
	b.WriteString("--- expected\n")
	b.WriteString("+++ actual\n")
	for _, op := range ops {
		switch op.kind {
		case equal:
			continue
		case removed:
			fmt.Fprintf(&b, "- %s\n", op.line)
		case added:
			fmt.Fprintf(&b, "+ %s\n", op.line)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

type diffKind int

const (
	equal diffKind = iota
	removed
	added
)

type diffOp struct {
	kind diffKind
	line string
}

func shortestEditScript(a, b []string) []diffOp {
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}

	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{kind: equal, line: a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{kind: removed, line: a[i]})
			i++
		default:
			ops = append(ops, diffOp{kind: added, line: b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		ops = append(ops, diffOp{kind: removed, line: a[i]})
	}
	for ; j < len(b); j++ {
		ops = append(ops, diffOp{kind: added, line: b[j]})
	}
	return ops
}

package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/4LAU/apisniff-go/internal/auth"
	"github.com/4LAU/apisniff-go/internal/model"
)

type Inventory struct {
	SchemaVersion int                    `json:"schema_version"`
	Domain        string                 `json:"domain,omitempty"`
	TotalFlows    int                    `json:"total_flows"`
	TopEndpoints  []EndpointSummary      `json:"top_endpoints"`
	Categories    map[string]int         `json:"categories"`
	Hosts         map[string]int         `json:"hosts"`
	AuthPatterns  []auth.Pattern         `json:"auth_patterns,omitempty"`
	Cookies       []auth.ExtractedCookie `json:"cookies,omitempty"`
}

type EndpointSummary struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Count  int    `json:"count"`
}

func BuildInventory(flows []model.CapturedFlow, domain string) Inventory {
	return Inventory{
		SchemaVersion: 1,
		Domain:        domain,
		TotalFlows:    len(flows),
		TopEndpoints:  summarizeEndpoints(flows, 25),
		Categories:    summarizeCategories(flows),
		Hosts:         summarizeHosts(flows),
		AuthPatterns:  auth.Detect(flows),
		Cookies:       RedactCookies(auth.ExtractCookies(flows)),
	}
}

func RedactCookies(cookies []auth.ExtractedCookie) []auth.ExtractedCookie {
	out := make([]auth.ExtractedCookie, len(cookies))
	for i, cookie := range cookies {
		out[i] = cookie
		if out[i].Value != "" {
			out[i].Value = "[redacted]"
		}
	}
	return out
}

func WriteInventory(path string, inventory Inventory) error {
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func summarizeEndpoints(flows []model.CapturedFlow, limit int) []EndpointSummary {
	counts := map[string]int{}
	for _, flow := range flows {
		key := strings.ToUpper(flow.Method) + " " + model.NormalizePath(flow.Path)
		counts[key]++
	}
	keys := sortedKeysByCount(counts)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]EndpointSummary, 0, len(keys))
	for _, key := range keys {
		method, path, _ := strings.Cut(key, " ")
		out = append(out, EndpointSummary{Method: method, Path: path, Count: counts[key]})
	}
	return out
}

func summarizeCategories(flows []model.CapturedFlow) map[string]int {
	counts := map[string]int{}
	for _, flow := range flows {
		category := "uncategorized"
		for _, tag := range flow.Tags {
			if value, ok := strings.CutPrefix(tag, "category:"); ok {
				category = value
				break
			}
		}
		counts[category]++
	}
	return counts
}

func summarizeHosts(flows []model.CapturedFlow) map[string]int {
	counts := map[string]int{}
	for _, flow := range flows {
		if flow.Host != "" {
			counts[flow.Host]++
		}
	}
	return counts
}

func sortedKeysByCount(counts map[string]int) []string {
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
	return keys
}

func domainFromSession(bundleDir string, fallback string) string {
	if fallback != "" {
		return fallback
	}
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

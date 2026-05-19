package report

import (
	"bytes"
	"fmt"
	"sort"
)

func Markdown(inventory Inventory) []byte {
	var buf bytes.Buffer
	title := "API Sniff Report"
	if inventory.Domain != "" {
		title = "API Sniff Report: " + inventory.Domain
	}
	fmt.Fprintf(&buf, "# %s\n\n", title)
	fmt.Fprintf(&buf, "Total flows: %d\n\n", inventory.TotalFlows)

	if len(inventory.Categories) > 0 {
		fmt.Fprintln(&buf, "## Surface Categories")
		for _, key := range sortedMapKeys(inventory.Categories) {
			fmt.Fprintf(&buf, "- %s: %d\n", key, inventory.Categories[key])
		}
		fmt.Fprintln(&buf)
	}

	if len(inventory.TopEndpoints) > 0 {
		fmt.Fprintln(&buf, "## Top Endpoints")
		for _, endpoint := range inventory.TopEndpoints {
			fmt.Fprintf(&buf, "- `%s %s`: %d\n", endpoint.Method, endpoint.Path, endpoint.Count)
		}
		fmt.Fprintln(&buf)
	}

	if len(inventory.AuthPatterns) > 0 {
		fmt.Fprintln(&buf, "## Auth Patterns")
		for _, pattern := range inventory.AuthPatterns {
			fmt.Fprintf(&buf, "- %s (%s): %d\n", pattern.AuthType, pattern.Detail, pattern.FlowCount)
		}
		fmt.Fprintln(&buf)
	}

	if len(inventory.Cookies) > 0 {
		fmt.Fprintln(&buf, "## Cookies")
		for _, cookie := range inventory.Cookies {
			fmt.Fprintf(&buf, "- %s domain=%s path=%s source=%s value=[redacted]\n", cookie.Name, cookie.Domain, cookie.Path, cookie.Source)
		}
		fmt.Fprintln(&buf)
	}

	if len(inventory.Hosts) > 0 {
		fmt.Fprintln(&buf, "## Hosts")
		for _, key := range sortedMapKeys(inventory.Hosts) {
			fmt.Fprintf(&buf, "- %s: %d\n", key, inventory.Hosts[key])
		}
	}

	return buf.Bytes()
}

func sortedMapKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

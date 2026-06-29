package spec

import (
	"net"
	"net/url"
	"strings"

	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/model"
)

const includedForSpecTag = "spec:included"

type InclusionOptions struct {
	IncludeThirdParty bool
	IncludeCategories []string
	IncludeHosts      []string
}

func (o InclusionOptions) Enabled() bool {
	return o.IncludeThirdParty || len(o.IncludeCategories) > 0 || len(o.IncludeHosts) > 0
}

type SurfaceInventory struct {
	SchemaVersion int                    `json:"schema_version"`
	Domain        string                 `json:"domain,omitempty"`
	TotalFlows    int                    `json:"total_flows"`
	KeptFlows     int                    `json:"kept_flows"`
	DroppedFlows  int                    `json:"dropped_flows"`
	Categories    map[string]int         `json:"categories"`
	Actions       map[string]int         `json:"actions"`
	Hosts         map[string]int         `json:"hosts"`
	Flows         []SurfaceInventoryFlow `json:"flows"`
	Coverage      *CoverageReport        `json:"coverage,omitempty"`
}

type SurfaceInventoryFlow struct {
	Index          int                   `json:"index"`
	Method         string                `json:"method,omitempty"`
	Host           string                `json:"host,omitempty"`
	Path           string                `json:"path,omitempty"`
	ResponseStatus int                   `json:"response_status,omitempty"`
	ContentType    string                `json:"content_type,omitempty"`
	Action         string                `json:"action"`
	Category       model.SurfaceCategory `json:"category"`
	Reason         string                `json:"reason,omitempty"`
	APILike        bool                  `json:"api_like"`
	HostRole       string                `json:"host_role,omitempty"`
	Signals        []string              `json:"signals,omitempty"`
}

type classifiedFlow struct {
	flow   model.CapturedFlow
	result model.ClassifyResult
	kept   *model.CapturedFlow
}

func BuildSurfaceInventory(flows []model.CapturedFlow, domain string) SurfaceInventory {
	classified := classifyFlows(flows, classify.Must(domain))
	return buildSurfaceInventory(classified, domain)
}

func ApplyInclusionFilters(flows []model.CapturedFlow, domain string, opts InclusionOptions) ([]model.CapturedFlow, SurfaceInventory, error) {
	classifier, err := classify.New(domain)
	if err != nil {
		return nil, SurfaceInventory{}, err
	}

	classified := classifyFlows(flows, classifier)
	inventory := buildSurfaceInventory(classified, domain)
	normalized := normalizeInclusionOptions(opts)

	out := make([]model.CapturedFlow, 0, len(flows))
	for _, item := range classified {
		if item.result.Action == "keep" && item.kept != nil {
			// Classify already tags kept flows with their category.
			out = append(out, *item.kept)
			continue
		}
		if matchesInclusion(item.flow, item.result, normalized) {
			out = append(out, withSpecIncludedTag(withCategoryTag(item.flow, item.result.Category)))
		}
	}
	return out, inventory, nil
}

func classifyFlows(flows []model.CapturedFlow, classifier *classify.Classifier) []classifiedFlow {
	// Two passes: learn cross-flow evidence first so classification is
	// independent of flow order.
	for _, flow := range flows {
		classifier.Learn(flow)
	}
	out := make([]classifiedFlow, 0, len(flows))
	for _, flow := range flows {
		result, kept := classifier.Classify(flow)
		out = append(out, classifiedFlow{flow: flow, result: result, kept: kept})
	}
	return out
}

func buildSurfaceInventory(classified []classifiedFlow, domain string) SurfaceInventory {
	inventory := SurfaceInventory{
		SchemaVersion: 1,
		Domain:        domain,
		TotalFlows:    len(classified),
		Categories:    map[string]int{},
		Actions:       map[string]int{},
		Hosts:         map[string]int{},
		Flows:         make([]SurfaceInventoryFlow, 0, len(classified)),
	}

	for idx, item := range classified {
		result := item.result
		inventory.Actions[result.Action]++
		inventory.Categories[string(result.Category)]++
		if item.flow.Host != "" {
			inventory.Hosts[item.flow.Host]++
		}
		if result.Action == "keep" {
			inventory.KeptFlows++
		} else {
			inventory.DroppedFlows++
		}
		inventory.Flows = append(inventory.Flows, SurfaceInventoryFlow{
			Index:          idx,
			Method:         item.flow.Method,
			Host:           item.flow.Host,
			Path:           item.flow.Path,
			ResponseStatus: item.flow.ResponseStatus,
			ContentType:    item.flow.ContentType(),
			Action:         result.Action,
			Category:       result.Category,
			Reason:         result.Reason,
			APILike:        result.APILike,
			HostRole:       result.HostRole,
			Signals:        append([]string(nil), result.Signals...),
		})
	}

	return inventory
}

func normalizeInclusionOptions(opts InclusionOptions) InclusionOptions {
	normalized := InclusionOptions{IncludeThirdParty: opts.IncludeThirdParty}
	for _, category := range opts.IncludeCategories {
		category = normalizeCategory(category)
		if category != "" {
			normalized.IncludeCategories = append(normalized.IncludeCategories, category)
		}
	}
	for _, host := range opts.IncludeHosts {
		host = normalizeHost(host)
		if host != "" {
			normalized.IncludeHosts = append(normalized.IncludeHosts, host)
		}
	}
	return normalized
}

func matchesInclusion(flow model.CapturedFlow, result model.ClassifyResult, opts InclusionOptions) bool {
	if opts.IncludeThirdParty && result.Category == model.ThirdPartyAPI {
		return true
	}
	category := normalizeCategory(string(result.Category))
	for _, included := range opts.IncludeCategories {
		if category == included {
			return true
		}
	}
	host := normalizeHost(flow.Host)
	for _, included := range opts.IncludeHosts {
		if host == included {
			return true
		}
	}
	return false
}

func normalizeCategory(category string) string {
	category = strings.TrimSpace(strings.ToLower(category))
	category = strings.TrimPrefix(category, "category:")
	return category
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil {
			host = parsed.Host
		}
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.Count(host, ":") == 1 {
		before, _, _ := strings.Cut(host, ":")
		host = before
	}
	return strings.TrimSuffix(host, ".")
}

func withCategoryTag(flow model.CapturedFlow, category model.SurfaceCategory) model.CapturedFlow {
	categoryTag := "category:" + string(category)
	tags := make([]string, 0, len(flow.Tags)+1)
	for _, tag := range flow.Tags {
		if strings.HasPrefix(tag, "category:") {
			continue
		}
		if tag == categoryTag {
			continue
		}
		tags = append(tags, tag)
	}
	tags = append(tags, categoryTag)
	flow.Tags = tags
	return flow
}

func withSpecIncludedTag(flow model.CapturedFlow) model.CapturedFlow {
	for _, tag := range flow.Tags {
		if tag == includedForSpecTag {
			return flow
		}
	}
	flow.Tags = append(flow.Tags, includedForSpecTag)
	return flow
}

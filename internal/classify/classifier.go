package classify

import (
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/4LAU/apisniff/internal/model"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

var jsContentTypes = []string{"application/javascript", "text/javascript", "application/x-javascript"}
var droppableContentTypes = append(append([]string{}, jsContentTypes...),
	"text/css", "image/", "video/", "audio/", "font/",
	"application/font", "application/pdf", "application/wasm",
)

var telemetrySubdomainIndicators = []string{"analytics.", "smetrics.", "telemetry.", "metrics."}
var sensorDataPrefix = []byte(`{"sensor_data":`)

type indicators struct {
	Markers            []string `yaml:"markers"`
	AllowlistDomains   []string `yaml:"allowlist_domains"`
	AllowlistPaths     []string `yaml:"allowlist_paths"`
	DropPathSubstrings []string `yaml:"drop_path_substrings"`
	SameSiteDropPaths  []string `yaml:"same_site_drop_paths"`
}

type Classifier struct {
	mu                 sync.Mutex
	targetRD           string
	relatedDomains     map[string]struct{}
	allowlistDomains   []string
	allowlistPaths     []string
	antibotMarkers     []string
	dropPathSubstrings []string
	sameSiteDropPaths  []string
	noiseDomains       []string
}

func New(targetDomain string) (*Classifier, error) {
	var ind indicators
	if err := yaml.Unmarshal(challengeIndicatorsYAML, &ind); err != nil {
		return nil, err
	}
	var noise []string
	if err := yaml.Unmarshal(noiseDomainsYAML, &noise); err != nil {
		return nil, err
	}
	return &Classifier{
		targetRD:           ExtractRegisteredDomain(targetDomain),
		relatedDomains:     map[string]struct{}{},
		allowlistDomains:   ind.AllowlistDomains,
		allowlistPaths:     ind.AllowlistPaths,
		antibotMarkers:     ind.Markers,
		dropPathSubstrings: ind.DropPathSubstrings,
		sameSiteDropPaths:  ind.SameSiteDropPaths,
		noiseDomains:       noise,
	}, nil
}

func Must(targetDomain string) *Classifier {
	classifier, err := New(targetDomain)
	if err != nil {
		panic(err)
	}
	return classifier
}

// Learn ingests cross-flow evidence (CSP headers, referer/origin links)
// without classifying. Batch callers run Learn over every flow first so that
// Classify results do not depend on flow order; live capture, which cannot
// see the future, simply skips this pass and learns as it goes.
func (c *Classifier) Learn(flow model.CapturedFlow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.learnCSP(flow)
	c.learnRelated(flow)
}

func (c *Classifier) Classify(flow model.CapturedFlow) (model.ClassifyResult, *model.CapturedFlow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if flow.Method == "OPTIONS" {
		return model.ClassifyResult{Action: "drop", Category: model.Options, Reason: "CORS preflight"}, nil
	}

	tags := append([]string(nil), flow.Tags...)
	host := flow.Host
	path := flow.Path
	pathOnly := strings.SplitN(path, "?", 2)[0]

	allowlisted := c.isAllowlisted(flow)
	if allowlisted {
		tags = append(tags, "allowlisted")
	}

	if !allowlisted && matchesDomainList(host, c.noiseDomains) {
		return model.ClassifyResult{Action: "drop", Category: model.Telemetry, Reason: "noise_domain", HostRole: "third_party", Signals: []string{"noise_domain"}}, nil
	}

	c.learnCSP(flow)

	if !allowlisted && containsAny(pathOnly, c.dropPathSubstrings) {
		return model.ClassifyResult{Action: "drop", Category: model.Telemetry, Reason: "path_telemetry", Signals: []string{"path_telemetry"}}, nil
	}

	hostRole := c.hostRole(flow)
	if !allowlisted && hostRole == "third_party" {
		return model.ClassifyResult{Action: "drop", Category: model.ThirdPartyAPI, Reason: "third_party", HostRole: hostRole}, nil
	}

	if !allowlisted {
		ct := flow.ContentType()
		if contentTypeMatches(ct, droppableContentTypes) {
			if contentTypeMatches(ct, jsContentTypes) {
				markers := c.scanAntibotMarkers(flow.ResponseBody)
				if len(markers) >= 2 {
					tags = append(tags, "antibot_js")
				} else {
					return model.ClassifyResult{Action: "drop", Category: model.Static, Reason: "static_asset", HostRole: hostRole}, nil
				}
			} else {
				return model.ClassifyResult{Action: "drop", Category: model.Static, Reason: "static_asset", HostRole: hostRole}, nil
			}
		}
	}

	if !allowlisted && containsAny(pathOnly, c.sameSiteDropPaths) {
		return model.ClassifyResult{Action: "drop", Category: model.Telemetry, Reason: "same_site_noise", HostRole: hostRole, Signals: []string{"same_site_noise"}}, nil
	}

	if !allowlisted && flow.Method == "POST" && len(flow.RequestBody) >= len(sensorDataPrefix) && string(flow.RequestBody[:len(sensorDataPrefix)]) == string(sensorDataPrefix) {
		return model.ClassifyResult{Action: "drop", Category: model.Antibot, Reason: "same_site_noise", HostRole: hostRole, Signals: []string{"sensor_data"}}, nil
	}

	if !allowlisted && ExtractRegisteredDomain(host) == c.targetRD {
		hostLower := strings.ToLower(stripPort(host))
		for _, indicator := range telemetrySubdomainIndicators {
			if strings.HasPrefix(hostLower, indicator) || strings.Contains(hostLower, "."+indicator) {
				return model.ClassifyResult{Action: "drop", Category: model.Telemetry, Reason: "same_site_noise", HostRole: hostRole, Signals: []string{"telemetry_subdomain"}}, nil
			}
		}
	}

	kept := flow
	kept.Tags = tags
	category := c.surfaceCategory(kept, hostRole, tags)
	kept.Tags = tagCategory(tags, category)
	return model.ClassifyResult{
		Action:   "keep",
		Category: category,
		Reason:   "kept",
		APILike:  isAPILike(kept),
		HostRole: hostRole,
		Signals:  tags,
	}, &kept
}

// tagCategory returns tags with exactly one category tag: any existing
// category tag is replaced. Kept flows carry their category so every consumer
// (capture writers, spec generation, inventory) reads one convention.
func tagCategory(tags []string, category model.SurfaceCategory) []string {
	out := make([]string, 0, len(tags)+1)
	for _, tag := range tags {
		if strings.HasPrefix(tag, "category:") {
			continue
		}
		out = append(out, tag)
	}
	return append(out, "category:"+string(category))
}

func (c *Classifier) isAllowlisted(flow model.CapturedFlow) bool {
	if matchesDomainList(flow.Host, c.allowlistDomains) {
		return true
	}
	pathOnly := strings.SplitN(flow.Path, "?", 2)[0]
	return containsAny(pathOnly, c.allowlistPaths)
}

func (c *Classifier) hostRole(flow model.CapturedFlow) string {
	rd := ExtractRegisteredDomain(flow.Host)
	if rd == c.targetRD {
		return "target"
	}
	if _, ok := c.relatedDomains[rd]; ok {
		return "same_site"
	}
	if c.learnRelated(flow) {
		return "same_site"
	}
	return "third_party"
}

// learnRelated marks the flow's registered domain as same-site when the
// request's referer/origin points at the target. Reports whether it did.
func (c *Classifier) learnRelated(flow model.CapturedFlow) bool {
	rd := ExtractRegisteredDomain(flow.Host)
	if rd == "" || rd == c.targetRD {
		return false
	}
	for _, header := range []string{"referer", "origin"} {
		if value := model.GetHeader(flow.RequestHeaders, header); value != "" {
			host := hostFromURL(value)
			if host != "" && ExtractRegisteredDomain(host) == c.targetRD {
				c.relatedDomains[rd] = struct{}{}
				return true
			}
		}
	}
	return false
}

func (c *Classifier) learnCSP(flow model.CapturedFlow) {
	csp := model.GetHeader(flow.ResponseHeaders, "content-security-policy")
	if csp == "" {
		return
	}
	for _, directive := range strings.Split(csp, ";") {
		parts := strings.Fields(strings.TrimSpace(directive))
		if len(parts) < 2 {
			continue
		}
		for _, token := range parts[1:] {
			token = strings.Trim(token, "'\"")
			if token == "" || !strings.Contains(token, ".") {
				continue
			}
			host := strings.TrimPrefix(token, "*.")
			if strings.Contains(host, "//") {
				host = strings.SplitN(host, "//", 2)[1]
				host = strings.SplitN(host, "/", 2)[0]
				host = strings.SplitN(host, ":", 2)[0]
			}
			if host == "" || !strings.Contains(host, ".") {
				continue
			}
			rd := ExtractRegisteredDomain(host)
			if rd != "" && rd != c.targetRD && !matchesDomainList(host, c.noiseDomains) {
				c.relatedDomains[rd] = struct{}{}
			}
		}
	}
}

func (c *Classifier) scanAntibotMarkers(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	if len(body) > 500000 {
		body = body[:500000]
	}
	text := string(body)
	var markers []string
	for _, marker := range c.antibotMarkers {
		if strings.Contains(text, marker) {
			markers = append(markers, marker)
		}
	}
	return markers
}

func (c *Classifier) surfaceCategory(flow model.CapturedFlow, hostRole string, tags []string) model.SurfaceCategory {
	for _, tag := range tags {
		if tag == "antibot_js" || tag == "allowlisted" {
			return model.Antibot
		}
	}
	path := strings.ToLower(strings.SplitN(flow.Path, "?", 2)[0])
	if isAuthPath(path) {
		return model.Auth
	}
	if isAPILike(flow) {
		if hostRole == "third_party" {
			return model.ThirdPartyAPI
		}
		return model.BusinessAPI
	}
	return model.UnknownAPILike
}

func ExtractRegisteredDomain(hostname string) string {
	h := strings.ToLower(strings.TrimSuffix(stripPort(hostname), "."))
	if h == "" {
		return h
	}
	if ip := net.ParseIP(h); ip != nil {
		return h
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err == nil && etld1 != "" {
		return etld1
	}
	return h
}

func stripPort(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return h
	}
	if parsedHost, _, err := net.SplitHostPort(h); err == nil {
		return parsedHost
	}
	if strings.Count(h, ":") == 1 {
		if before, _, ok := strings.Cut(h, ":"); ok {
			return before
		}
	}
	return h
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func matchesDomainList(domain string, domainList []string) bool {
	d := strings.ToLower(stripPort(domain))
	for _, entry := range domainList {
		entry = strings.ToLower(entry)
		if d == entry || strings.HasSuffix(d, "."+entry) {
			return true
		}
	}
	return false
}

func containsAny(value string, fragments []string) bool {
	for _, fragment := range fragments {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func contentTypeMatches(contentType string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

func isAPILike(flow model.CapturedFlow) bool {
	ct := flow.ContentType()
	path := strings.ToLower(flow.Path)
	if strings.Contains(ct, "json") {
		return true
	}
	if strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") || strings.Contains(path, "/v2/") || strings.Contains(path, "/graphql") {
		return true
	}
	if isProgrammaticFetch(flow) {
		return true
	}
	switch flow.Method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// isProgrammaticFetch reports whether the browser issued this request from
// JavaScript (fetch/XHR) rather than a top-level navigation. Such a request is
// API surface no matter what content-type it returns — a server-rendered HTML
// fragment fetched by script is exactly as much API as a JSON endpoint. A page
// navigation sends sec-fetch-dest=document and is excluded.
func isProgrammaticFetch(flow model.CapturedFlow) bool {
	if strings.EqualFold(model.GetHeader(flow.RequestHeaders, "x-requested-with"), "XMLHttpRequest") {
		return true
	}
	return strings.EqualFold(model.GetHeader(flow.RequestHeaders, "sec-fetch-dest"), "empty")
}

func isAuthPath(path string) bool {
	for _, segment := range []string{"auth", "login", "token", "oauth", "signup", "register"} {
		if containsPathSegment(path, segment) {
			return true
		}
	}
	return false
}

func containsPathSegment(path, segment string) bool {
	target := "/" + segment
	start := 0
	for {
		idx := strings.Index(path[start:], target)
		if idx < 0 {
			return false
		}
		idx += start
		end := idx + len(target)
		if end >= len(path) {
			return true
		}
		next := path[end]
		if next == '/' || next == '?' || next == '#' {
			return true
		}
		start = idx + 1
	}
}

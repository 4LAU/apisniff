package classify

import (
	"net"
	"net/url"
	"strings"

	"github.com/4LAU/apisniff-go/internal/model"
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

func (c *Classifier) Classify(flow model.CapturedFlow) (model.ClassifyResult, *model.CapturedFlow) {
	if flow.Method == "OPTIONS" {
		return model.ClassifyResult{Action: "drop", Category: model.Options, Reason: "CORS preflight"}, nil
	}

	tags := []string{}
	host := flow.Host
	path := flow.Path
	pathOnly := strings.SplitN(path, "?", 2)[0]

	allowlistType := c.checkAllowlist(flow)
	if allowlistType != "" {
		tags = append(tags, "allowlisted")
	}

	if allowlistType == "" && matchesDomainList(host, c.noiseDomains) {
		return model.ClassifyResult{Action: "drop", Category: model.Telemetry, Reason: "noise_domain", HostRole: "third_party", Signals: []string{"noise_domain"}}, nil
	}

	c.learnCSP(flow)

	if allowlistType != "domain" && allowlistType != "path" && containsAny(pathOnly, c.dropPathSubstrings) {
		return model.ClassifyResult{Action: "drop", Category: model.Telemetry, Reason: "path_telemetry", Signals: []string{"path_telemetry"}}, nil
	}

	hostRole := c.hostRole(flow)
	if allowlistType == "" && hostRole == "third_party" {
		return model.ClassifyResult{Action: "drop", Category: model.ThirdPartyAPI, Reason: "third_party", HostRole: hostRole}, nil
	}

	if allowlistType != "domain" && allowlistType != "path" {
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

	if allowlistType != "domain" && allowlistType != "path" && containsAny(pathOnly, c.sameSiteDropPaths) {
		return model.ClassifyResult{Action: "drop", Category: model.Telemetry, Reason: "same_site_noise", HostRole: hostRole, Signals: []string{"same_site_noise"}}, nil
	}

	if allowlistType == "" && flow.Method == "POST" && len(flow.RequestBody) >= len(sensorDataPrefix) && string(flow.RequestBody[:len(sensorDataPrefix)]) == string(sensorDataPrefix) {
		return model.ClassifyResult{Action: "drop", Category: model.Antibot, Reason: "same_site_noise", HostRole: hostRole, Signals: []string{"sensor_data"}}, nil
	}

	if allowlistType == "" && ExtractRegisteredDomain(host) == c.targetRD {
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
	return model.ClassifyResult{
		Action:   "keep",
		Category: category,
		Reason:   "kept",
		APILike:  isAPILike(kept),
		HostRole: hostRole,
		Signals:  tags,
	}, &kept
}

func (c *Classifier) checkAllowlist(flow model.CapturedFlow) string {
	if matchesDomainList(flow.Host, c.allowlistDomains) {
		return "domain"
	}
	pathOnly := strings.SplitN(flow.Path, "?", 2)[0]
	if containsAny(pathOnly, c.allowlistPaths) {
		return "path"
	}
	return ""
}

func (c *Classifier) hostRole(flow model.CapturedFlow) string {
	rd := ExtractRegisteredDomain(flow.Host)
	if rd == c.targetRD {
		return "target"
	}
	if _, ok := c.relatedDomains[rd]; ok {
		return "same_site"
	}
	for _, header := range []string{"referer", "origin"} {
		if value := model.GetHeader(flow.RequestHeaders, header); value != "" {
			host := hostFromURL(value)
			if host != "" && ExtractRegisteredDomain(host) == c.targetRD {
				c.relatedDomains[rd] = struct{}{}
				return "same_site"
			}
		}
	}
	return "third_party"
}

func (c *Classifier) learnCSP(flow model.CapturedFlow) {
	csp := model.GetHeader(flow.ResponseHeaders, "content-security-policy")
	if csp == "" {
		return
	}
	for _, directive := range strings.Split(csp, ";") {
		parts := strings.Fields(strings.TrimSpace(directive))
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
	text := string(body)
	if len(text) > 500000 {
		text = text[:500000]
	}
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
	switch flow.Method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func isAuthPath(path string) bool {
	for _, fragment := range []string{"/auth", "/login", "/token", "/oauth", "/signup", "/register"} {
		if strings.Contains(path, fragment) {
			return true
		}
	}
	return false
}

package model

import (
	"strings"
	"time"
)

type ProbeVerdict int

const (
	NoProtection ProbeVerdict = iota
	ClientDependent
	JSChallenge
	FullBlock
)

func (v ProbeVerdict) String() string {
	switch v {
	case NoProtection:
		return "no_protection"
	case ClientDependent:
		return "client_dependent"
	case JSChallenge:
		return "js_challenge"
	case FullBlock:
		return "full_block"
	default:
		return "unknown"
	}
}

type ProbeResult struct {
	Variant string            `json:"variant"`
	Status  int               `json:"status,omitempty"`
	Latency time.Duration     `json:"-"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"-"`
	Error   string            `json:"error,omitempty"`
}

func (r ProbeResult) ElapsedMS() float64 {
	return float64(r.Latency.Microseconds()) / 1000
}

func (r ProbeResult) IsBlocked() bool {
	if r.Error != "" || r.Status == 0 {
		return true
	}
	switch r.Status {
	case 403, 429, 503, 999:
		return true
	default:
		return r.IsChallenge()
	}
}

func (r ProbeResult) IsChallenge() bool {
	if len(r.Body) == 0 {
		return false
	}
	text := strings.ToLower(string(r.Body))
	if len(text) > 50000 {
		text = text[:50000]
	}
	for _, marker := range []string{
		"challenges.cloudflare.com",
		"challenge-platform",
		"managed_challenge",
		"jschl_vc",
		"_cf_chl_opt",
		"cf-please-wait",
		"captcha",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

type ProbeAssessment struct {
	URL            string           `json:"url"`
	Verdict        ProbeVerdict     `json:"-"`
	Recommendation string           `json:"recommendation"`
	Results        []ProbeResult    `json:"results"`
	Vendors        []VendorMatch    `json:"vendors,omitempty"`
	GraphQL        *GraphQLResult   `json:"graphql,omitempty"`
	RateLimit      *RateLimitResult `json:"rate_limit,omitempty"`
}

type GraphQLResult struct {
	Endpoints     []string `json:"endpoints"`
	Introspection bool     `json:"introspection"`
}

type VendorMatch struct {
	Vendor     string   `json:"vendor"`
	Confidence string   `json:"confidence"`
	Signals    []string `json:"signals,omitempty"`
}

type RateLimitResult struct {
	RequestsSent   int     `json:"requests_sent"`
	FirstBlockAt   int     `json:"first_block_at,omitempty"`
	BlockStatus    int     `json:"block_status,omitempty"`
	RetryAfter     string  `json:"retry_after,omitempty"`
	MedianMS       float64 `json:"median_ms"`
	SilentThrottle bool    `json:"silent_throttle"`
}

type SurfaceCategory string

const (
	BusinessAPI    SurfaceCategory = "business_api"
	Auth           SurfaceCategory = "auth"
	Antibot        SurfaceCategory = "antibot"
	Captcha        SurfaceCategory = "captcha"
	Telemetry      SurfaceCategory = "telemetry"
	ThirdPartyAPI  SurfaceCategory = "third_party_api"
	Static         SurfaceCategory = "static"
	NonAPI         SurfaceCategory = "non_api"
	UnknownAPILike SurfaceCategory = "unknown_api_like"
	Options        SurfaceCategory = "options"
)

type ClassifyResult struct {
	Action   string          `json:"action"`
	Category SurfaceCategory `json:"category"`
	Reason   string          `json:"reason,omitempty"`
	APILike  bool            `json:"api_like"`
	HostRole string          `json:"host_role,omitempty"`
	Signals  []string        `json:"signals,omitempty"`
}

type SessionStats struct {
	Domain          string         `json:"domain"`
	StartedAt       string         `json:"started_at"`
	DurationSeconds float64        `json:"duration_seconds"`
	TotalFlows      int            `json:"total_flows"`
	KeptFlows       int            `json:"kept_flows"`
	Dropped         map[string]int `json:"dropped"`
}

type ReplayOutcome string

const (
	ReplayMatch       ReplayOutcome = "match"
	ReplayDrift       ReplayOutcome = "drift"
	ReplayAuthExpired ReplayOutcome = "auth_expired"
	ReplayBlocked     ReplayOutcome = "blocked"
	ReplayError       ReplayOutcome = "error"
)

type ReplayResult struct {
	Outcome ReplayOutcome `json:"outcome"`
	Method  string        `json:"method,omitempty"`
	Path    string        `json:"path,omitempty"`
	Details string        `json:"details,omitempty"`
}

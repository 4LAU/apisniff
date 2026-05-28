package vendor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/4LAU/apisniff/internal/model"
)

type Signal struct {
	Type    string `json:"type"`
	Key     string `json:"key,omitempty"`
	Value   any    `json:"value,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Prefix  string `json:"prefix,omitempty"`

	re *regexp.Regexp
}

type signature struct {
	High   []Signal `json:"high"`
	Medium []Signal `json:"medium"`
	Low    []Signal `json:"low"`
}

type Detector struct {
	signatures map[string]signature
}

func NewDetector() (*Detector, error) {
	var signatures map[string]signature
	if err := json.Unmarshal(signaturesJSON, &signatures); err != nil {
		return nil, err
	}
	for vendor, sig := range signatures {
		for _, group := range []*[]Signal{&sig.High, &sig.Medium, &sig.Low} {
			for i := range *group {
				pattern := (*group)[i].Pattern
				if pattern == "" {
					continue
				}
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("%s signature %q is not RE2-compatible: %w", vendor, pattern, err)
				}
				(*group)[i].re = re
			}
		}
		signatures[vendor] = sig
	}
	return &Detector{signatures: signatures}, nil
}

func MustDetector() *Detector {
	detector, err := NewDetector()
	if err != nil {
		panic(err)
	}
	return detector
}

func (d *Detector) Match(headers map[string]string, body []byte, status int) []model.VendorMatch {
	if d == nil {
		return nil
	}
	lowerHeaders := normalizeHeaders(headers)
	cookies := cookieNames(lowerHeaders)
	truncated := body
	if len(truncated) > 500000 {
		truncated = truncated[:500000]
	}
	bodyText := strings.ToLower(string(truncated))

	var matches []model.VendorMatch
	for name, sig := range d.signatures {
		signals := map[string]struct{}{}
		highest := ""
		for confidence, group := range map[string][]Signal{
			"high":   sig.High,
			"medium": sig.Medium,
			"low":    sig.Low,
		} {
			for _, signal := range group {
				if signal.matches(lowerHeaders, cookies, bodyText, status) {
					signals[signal.label(confidence)] = struct{}{}
					if BetterConfidence(confidence, highest) {
						highest = confidence
					}
				}
			}
		}
		if len(signals) == 0 {
			continue
		}
		if highest == "" {
			highest = "low"
		}
		matches = append(matches, model.VendorMatch{
			Vendor:     name,
			Confidence: highest,
			Signals:    orderedKeys(signals),
		})
	}
	return matches
}

func (s Signal) matches(headers map[string]string, cookies map[string]struct{}, body string, status int) bool {
	key := strings.ToLower(s.Key)
	value := strings.ToLower(fmt.Sprint(s.Value))
	switch s.Type {
	case "header_present":
		_, ok := headers[key]
		return ok
	case "header_value":
		return strings.EqualFold(headers[key], fmt.Sprint(s.Value))
	case "header_starts_with":
		return strings.HasPrefix(strings.ToLower(headers[key]), value)
	case "header_name_regex":
		for name := range headers {
			if s.re != nil && s.re.MatchString(name) {
				return true
			}
		}
	case "cookie_name":
		_, ok := cookies[strings.ToLower(s.Key)]
		return ok
	case "cookie_name_regex":
		for name := range cookies {
			if s.re != nil && s.re.MatchString(name) {
				return true
			}
		}
	case "cookie_name_startswith":
		prefix := strings.ToLower(s.Prefix)
		for name := range cookies {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	case "body_contains":
		return strings.Contains(body, value)
	case "status_code":
		return fmt.Sprint(status) == fmt.Sprint(s.Value)
	}
	return false
}

func (s Signal) label(confidence string) string {
	switch s.Type {
	case "header_present", "header_value", "header_starts_with":
		return confidence + ":header:" + strings.ToLower(s.Key)
	case "header_name_regex":
		return confidence + ":header_regex:" + s.Pattern
	case "cookie_name", "cookie_name_regex", "cookie_name_startswith":
		if s.Key != "" {
			return confidence + ":cookie:" + strings.ToLower(s.Key)
		}
		if s.Prefix != "" {
			return confidence + ":cookie_prefix:" + strings.ToLower(s.Prefix)
		}
		return confidence + ":cookie_regex:" + s.Pattern
	case "body_contains":
		return confidence + ":body:" + fmt.Sprint(s.Value)
	case "status_code":
		return confidence + ":status:" + fmt.Sprint(s.Value)
	default:
		return confidence + ":" + s.Type
	}
}

func normalizeHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[strings.ToLower(key)] = value
	}
	return out
}

func cookieNames(headers map[string]string) map[string]struct{} {
	out := map[string]struct{}{}
	for key, value := range headers {
		if key != "set-cookie" && key != "cookie" {
			continue
		}
		if key == "set-cookie" {
			individual := splitSetCookieValues(value)
			resp := &http.Response{Header: http.Header{"Set-Cookie": individual}}
			for _, cookie := range resp.Cookies() {
				out[strings.ToLower(cookie.Name)] = struct{}{}
			}
		} else {
			for _, part := range strings.Split(value, ";") {
				name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
				if name != "" && !isCookieAttribute(name) {
					out[strings.ToLower(name)] = struct{}{}
				}
			}
		}
	}
	return out
}

func splitSetCookieValues(joined string) []string {
	lines := strings.Split(joined, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	if len(result) == 0 && joined != "" {
		result = append(result, joined)
	}
	return result
}

func isCookieAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "expires", "max-age", "domain", "path", "samesite", "secure", "httponly":
		return true
	default:
		return false
	}
}

func BetterConfidence(next, current string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	return rank[next] > rank[current]
}

func orderedKeys(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

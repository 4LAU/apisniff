package auth

import (
	"net/url"
	"sort"
	"strings"

	"github.com/4LAU/apisniff/internal/model"
)

var sessionCookieNames = map[string]struct{}{
	"session": {}, "sessionid": {}, "sid": {}, "jsessionid": {}, "phpsessid": {},
	"connect.sid": {}, "_session_id": {}, "laravel_session": {},
}

var apiKeyHeaders = map[string]struct{}{"x-api-key": {}, "api-key": {}, "apikey": {}}
var apiKeyQueryParams = map[string]struct{}{"api_key": {}, "apikey": {}, "key": {}}
var tokenPaths = map[string]struct{}{"/oauth/token": {}, "/auth/token": {}, "/token": {}}

type Pattern struct {
	AuthType  string `json:"auth_type"`
	Detail    string `json:"detail"`
	FlowCount int    `json:"flow_count"`
}

type ExtractedCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	HostOnly bool   `json:"host_only"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	Source   string `json:"source"`
}

func Detect(flows []model.CapturedFlow) []Pattern {
	counts := map[[2]string]int{}
	for _, flow := range flows {
		headers := lowerHeaders(flow.RequestHeaders)
		pathPart, query, _ := strings.Cut(flow.Path, "?")
		path := strings.TrimRight(pathPart, "/")

		authHeader := strings.ToLower(headers["authorization"])
		if strings.HasPrefix(authHeader, "bearer ") {
			counts[[2]string{"bearer", "authorization: bearer"}]++
		} else if strings.HasPrefix(authHeader, "basic ") {
			counts[[2]string{"basic", "authorization: basic"}]++
		}

		for header := range apiKeyHeaders {
			if _, ok := headers[header]; ok {
				counts[[2]string{"api_key_header", header}]++
			}
		}

		values, _ := url.ParseQuery(query)
		for param := range apiKeyQueryParams {
			if _, ok := values[param]; ok {
				counts[[2]string{"api_key_query", param}]++
			}
		}

		for _, part := range strings.Split(headers["cookie"], ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if _, ok := sessionCookieNames[name]; ok {
				counts[[2]string{"session_cookie", name}]++
			}
		}

		if _, ok := tokenPaths[strings.ToLower(path)]; ok {
			counts[[2]string{"token_endpoint", path}]++
		}
	}

	patterns := make([]Pattern, 0, len(counts))
	for key, count := range counts {
		patterns = append(patterns, Pattern{AuthType: key[0], Detail: key[1], FlowCount: count})
	}
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].FlowCount == patterns[j].FlowCount {
			if patterns[i].AuthType == patterns[j].AuthType {
				return patterns[i].Detail < patterns[j].Detail
			}
			return patterns[i].AuthType < patterns[j].AuthType
		}
		return patterns[i].FlowCount > patterns[j].FlowCount
	})
	return patterns
}

func ExtractCookies(flows []model.CapturedFlow) []ExtractedCookie {
	sortedFlows := append([]model.CapturedFlow(nil), flows...)
	sort.Slice(sortedFlows, func(i, j int) bool {
		return sortedFlows[i].Timestamp < sortedFlows[j].Timestamp
	})
	seen := map[[3]string]struct {
		ts     float64
		cookie ExtractedCookie
	}{}
	for _, flow := range sortedFlows {
		headers := lowerHeaders(flow.RequestHeaders)
		if cookieHeader := headers["cookie"]; cookieHeader != "" {
			for _, part := range strings.Split(cookieHeader, ";") {
				part = strings.TrimSpace(part)
				if !strings.Contains(part, "=") {
					continue
				}
				name, value, _ := strings.Cut(part, "=")
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				cookie := ExtractedCookie{Name: name, Value: strings.TrimSpace(value), Domain: flow.Host, HostOnly: true, Path: "/", Source: "request"}
				seen[[3]string{cookie.Name, cookie.Domain, cookie.Path}] = struct {
					ts     float64
					cookie ExtractedCookie
				}{flow.Timestamp, cookie}
			}
		}
		responseHeaders := lowerHeaders(flow.ResponseHeaders)
		if setCookie := responseHeaders["set-cookie"]; setCookie != "" {
			for _, line := range strings.Split(setCookie, "\n") {
				if cookie, ok := parseSetCookie(line, flow.Host); ok {
					seen[[3]string{cookie.Name, cookie.Domain, cookie.Path}] = struct {
						ts     float64
						cookie ExtractedCookie
					}{flow.Timestamp, cookie}
				}
			}
		}
	}
	values := make([]struct {
		ts     float64
		cookie ExtractedCookie
	}, 0, len(seen))
	for _, value := range seen {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ts < values[j].ts })
	cookies := make([]ExtractedCookie, 0, len(values))
	for _, value := range values {
		cookies = append(cookies, value.cookie)
	}
	return cookies
}

func parseSetCookie(raw string, host string) (ExtractedCookie, bool) {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return ExtractedCookie{}, false
	}
	nameValue := strings.TrimSpace(parts[0])
	if !strings.Contains(nameValue, "=") {
		return ExtractedCookie{}, false
	}
	name, value, _ := strings.Cut(nameValue, "=")
	name = strings.TrimSpace(name)
	if name == "" {
		return ExtractedCookie{}, false
	}
	cookie := ExtractedCookie{Name: name, Value: value, Domain: host, HostOnly: true, Path: "/", Source: "response"}
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		key, val, hasValue := strings.Cut(attr, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch {
		case key == "domain" && hasValue:
			cookie.Domain = strings.TrimPrefix(val, ".")
			cookie.HostOnly = false
		case key == "path" && hasValue:
			if val != "" {
				cookie.Path = val
			}
		case key == "secure":
			cookie.Secure = true
		}
	}
	return cookie, true
}

func lowerHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[strings.ToLower(key)] = value
	}
	return out
}

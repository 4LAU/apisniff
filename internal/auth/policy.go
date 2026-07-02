package auth

import (
	"net/url"
	"regexp"
	"strings"
)

// Credential-forwarding policy: what replay refuses to send when
// --forward-auth is off. Deliberately broader than the detection vocabulary
// in detector.go — detection needs precision, stripping needs recall.

var credentialQueryRe = regexp.MustCompile(`(?i)(password|passwd|(^|[_-])pwd([_-]|$)|(^|[_-])secret([_-]|$)|credential|api[_-]?key|(^|[_-])key([_-]|$)|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|client[_-]?secret|(^|[_-])token([_-]|$)|(^|[_-])auth([_-]|$)|(^|[_-])sig(nature)?([_-]|$)|(^|[_-])session([_-]?id)?([_-]|$)|(^|[_-])sid([_-]|$)|(^|[_-])jwt([_-]|$)|(^|[_-])bearer([_-]|$))`)

// IsCredentialQueryParam reports whether a query parameter name is treated
// as a credential by the forwarding policy.
func IsCredentialQueryParam(name string) bool {
	return credentialQueryRe.MatchString(strings.TrimSpace(name))
}

// IsCredentialHeader reports whether a request header carries credentials.
func IsCredentialHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower == "cookie" ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "api-key") ||
		strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "auth-token") ||
		strings.Contains(lower, "access-token") ||
		strings.Contains(lower, "csrf-token") ||
		strings.Contains(lower, "xsrf-token")
}

// StripCredentialQueryParams removes credential query parameters from rawURL,
// preserving the order and encoding of the remaining parameters. Unparseable
// URLs are returned unchanged — the caller's request construction will
// surface the error.
func StripCredentialQueryParams(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return rawURL
	}
	pairs := strings.Split(parsed.RawQuery, "&")
	kept := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		name, _, _ := strings.Cut(pair, "=")
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		if IsCredentialQueryParam(name) {
			continue
		}
		kept = append(kept, pair)
	}
	parsed.RawQuery = strings.Join(kept, "&")
	return parsed.String()
}

// StripURLCredentials removes both credential query parameters (see
// StripCredentialQueryParams) and Basic-auth userinfo (user:pass@host) from
// rawURL. The replay request path uses this when --forward-auth is off:
// without clearing userinfo, net/http resends captured credentials as an
// Authorization: Basic header, defeating the flag. Unparseable URLs are
// returned unchanged — the caller's request construction will surface the
// error.
func StripURLCredentials(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.User = nil
	return StripCredentialQueryParams(parsed.String())
}

package model

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	uuidRe       = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	numericRe    = regexp.MustCompile(`^\d+$`)
	hexRe        = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	prefixedIDRe = regexp.MustCompile(`^[a-z]{1,8}_[A-Za-z0-9]{12,}$`)
	opaqueTokRe  = regexp.MustCompile(`^[A-Za-z0-9]{20,}$`)
)

type CapturedFlow struct {
	Method          string            `json:"method"`
	Host            string            `json:"host"`
	Path            string            `json:"path"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     []byte            `json:"-"`
	ResponseStatus  int               `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    []byte            `json:"-"`
	BodyEncoding    string            `json:"_body_encoding"`
	Tags            []string          `json:"tags"`
	Timestamp       float64           `json:"timestamp"`
}

type PathParam struct {
	Name          string
	ObservedValue string
}

type flowJSON struct {
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

func NewCapturedFlow(method, rawURL, host, path string) CapturedFlow {
	return CapturedFlow{
		Method:          method,
		Host:            strings.ToLower(host),
		Path:            path,
		URL:             rawURL,
		RequestHeaders:  map[string]string{},
		ResponseHeaders: map[string]string{},
		BodyEncoding:    "base64",
		Tags:            []string{},
		Timestamp:       float64(time.Now().UnixNano()) / 1e9,
	}
}

func (f CapturedFlow) MarshalJSON() ([]byte, error) {
	bodyEncoding := f.BodyEncoding
	if bodyEncoding == "" {
		bodyEncoding = "base64"
	}
	return json.Marshal(flowJSON{
		Method:          f.Method,
		Host:            f.Host,
		Path:            f.Path,
		URL:             f.URL,
		RequestHeaders:  nonNilMap(f.RequestHeaders),
		RequestBody:     encodeBody(f.RequestBody),
		ResponseStatus:  f.ResponseStatus,
		ResponseHeaders: nonNilMap(f.ResponseHeaders),
		ResponseBody:    encodeBody(f.ResponseBody),
		BodyEncoding:    bodyEncoding,
		Tags:            nonNilSlice(f.Tags),
		Timestamp:       f.Timestamp,
	})
}

func (f *CapturedFlow) UnmarshalJSON(data []byte) error {
	var wire flowJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	req, err := decodeBody(wire.RequestBody, wire.BodyEncoding)
	if err != nil {
		return err
	}
	resp, err := decodeBody(wire.ResponseBody, wire.BodyEncoding)
	if err != nil {
		return err
	}
	*f = CapturedFlow{
		Method:          wire.Method,
		Host:            wire.Host,
		Path:            wire.Path,
		URL:             wire.URL,
		RequestHeaders:  nonNilMap(wire.RequestHeaders),
		RequestBody:     req,
		ResponseStatus:  wire.ResponseStatus,
		ResponseHeaders: nonNilMap(wire.ResponseHeaders),
		ResponseBody:    resp,
		BodyEncoding:    FirstNonEmpty(wire.BodyEncoding, "base64"),
		Tags:            nonNilSlice(wire.Tags),
		Timestamp:       wire.Timestamp,
	}
	return nil
}

func (f CapturedFlow) ToJSONL() (string, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (f CapturedFlow) ContentType() string {
	ct := GetHeader(f.ResponseHeaders, "content-type")
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = ct[:idx]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}

func GetHeader(headers map[string]string, name string) string {
	lower := strings.ToLower(name)
	if value, ok := headers[lower]; ok {
		return value
	}
	// Keys are stored lowercase by every loader; scan only as a fallback
	// for hand-written JSONL with mixed-case keys.
	for key, value := range headers {
		if strings.ToLower(key) == lower {
			return value
		}
	}
	return ""
}

func NormalizePath(path string) string {
	normalized, _ := NormalizePathWithParams(path)
	return normalized
}

func NormalizePathWithParams(path string) (string, []PathParam) {
	normalized, params, _ := normalizePathSegments(path, false)
	return normalized, params
}

// NormalizeSpecPath is the strict variant used for OpenAPI paths: it requires
// a leading slash and canonicalizes `{template}` segments, rejecting
// malformed ones. Both variants share one walker so endpoint names cannot
// drift between analyze/report output and the generated spec.
func NormalizeSpecPath(path string) (string, []PathParam, bool) {
	return normalizePathSegments(path, true)
}

var pathTemplateNameRe = regexp.MustCompile(`^\{[0-9A-Za-z_.-]+\}$`)

func normalizePathSegments(path string, templates bool) (string, []PathParam, bool) {
	pathPart := strings.SplitN(path, "?", 2)[0]
	if templates && !strings.HasPrefix(pathPart, "/") {
		return "", nil, false
	}
	parts := strings.Split(pathPart, "/")
	params := []PathParam{}
	nameCounts := map[string]int{}
	previousStatic := ""
	for i, part := range parts {
		if part == "" {
			continue
		}
		switch {
		case templates && strings.ContainsAny(part, "{}"):
			if !pathTemplateNameRe.MatchString(part) {
				return "", nil, false
			}
			name := canonicalParamName(previousStatic, nameCounts)
			parts[i] = "{" + name + "}"
			params = append(params, PathParam{Name: name})
		case IsDynamicSegment(part):
			name := canonicalParamName(previousStatic, nameCounts)
			parts[i] = "{" + name + "}"
			params = append(params, PathParam{Name: name, ObservedValue: part})
		default:
			previousStatic = part
		}
	}
	normalized := strings.Join(parts, "/")
	if normalized == "" {
		normalized = "/"
	}
	return normalized, params, true
}

func IsDynamicSegment(part string) bool {
	return uuidRe.MatchString(part) || numericRe.MatchString(part) || hexRe.MatchString(part) ||
		isPrefixedOpaqueID(part) || isHighEntropyToken(part)
}

func charClasses(s string) (hasDigit, hasUpper, hasLower bool) {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		}
	}
	return
}

// isPrefixedOpaqueID matches Stripe-style resource IDs: a short lowercase
// prefix, an underscore, then a long base62 tail (cc_9BMquk…, cus_Nv8d…).
// The entropy gate (tail has a digit, or mixes upper- and lower-case) rejects
// the common readable snake_case segments like payment_processors or
// event_acknowledgements while accepting any vendor's random-tailed IDs — no
// vendor prefix is hardcoded. It is not perfectly precise: a readable tail that
// happens to carry a digit or mix case can still pass (see "Known precision
// limit" in the plan); the replay merge log is the backstop for that rare case.
func isPrefixedOpaqueID(part string) bool {
	if !prefixedIDRe.MatchString(part) {
		return false
	}
	tail := part[strings.IndexByte(part, '_')+1:]
	hasDigit, hasUpper, hasLower := charClasses(tail)
	return hasDigit || (hasUpper && hasLower)
}

// isHighEntropyToken matches a bare opaque identifier with no prefix to anchor
// on (ULID, nanoid, base62 key — length >= 20, pure base62, no separators).
// It demands a digit AND at least one letter: a digit excludes long lowercase
// route words like "receiptmanagementenabled", and requiring a letter excludes
// pure numerics (already handled by numericRe).
func isHighEntropyToken(part string) bool {
	if !opaqueTokRe.MatchString(part) {
		return false
	}
	hasDigit, hasUpper, hasLower := charClasses(part)
	return hasDigit && (hasUpper || hasLower)
}

func canonicalParamName(previousStatic string, counts map[string]int) string {
	base := "id"
	if previousStatic != "" {
		prefix := SingularizeSegment(previousStatic)
		if len(prefix) < 3 {
			prefix = previousStatic
		}
		if camel := CamelName(prefix); camel != "id" {
			base = camel + "Id"
		}
	}
	counts[base]++
	if counts[base] == 1 {
		return base
	}
	return base + strconv.Itoa(counts[base])
}

func SingularizeSegment(segment string) string {
	lower := strings.ToLower(segment)
	switch {
	case lower == "statuses":
		return "status"
	case strings.HasSuffix(lower, "sses") && len(segment) > 4:
		return segment[:len(segment)-2]
	case strings.HasSuffix(lower, "ies") && len(segment) > 4:
		return segment[:len(segment)-3] + "y"
	case strings.HasSuffix(lower, "s") && !strings.HasSuffix(lower, "ss") && !strings.HasSuffix(lower, "us") && len(segment) > 3:
		return segment[:len(segment)-1]
	default:
		return segment
	}
}

var nonAlnumRe = regexp.MustCompile(`[^0-9A-Za-z]+`)

func CamelName(value string) string {
	rawParts := nonAlnumRe.Split(value, -1)
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return "param"
	}
	out := strings.ToLower(parts[0])
	for _, part := range parts[1:] {
		out += strings.ToUpper(part[:1]) + part[1:]
	}
	return out
}

func ReplayDedupKey(path string) string {
	pathPart, query, ok := strings.Cut(path, "?")
	key := NormalizePath(pathPart)
	if !ok || query == "" {
		return key
	}
	names := map[string]struct{}{}
	for _, pair := range strings.Split(query, "&") {
		name, _, _ := strings.Cut(pair, "=")
		if name != "" {
			names[name] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	if len(ordered) == 0 {
		return key
	}
	parts := make([]string, 0, len(ordered))
	for _, name := range ordered {
		parts = append(parts, name+"={v}")
	}
	return key + "?" + strings.Join(parts, "&")
}

func encodeBody(body []byte) *string {
	if len(body) == 0 {
		return nil
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	return &encoded
}

func decodeBody(value *string, encoding string) ([]byte, error) {
	if value == nil || *value == "" {
		return nil, nil
	}
	if encoding == "" {
		return []byte(*value), nil
	}
	if encoding == "base64" {
		return base64.StdEncoding.DecodeString(*value)
	}
	return []byte(*value), nil
}

func nonNilMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	return in
}

func nonNilSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

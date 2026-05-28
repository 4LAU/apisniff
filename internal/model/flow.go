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
	uuidRe    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	numericRe = regexp.MustCompile(`^\d+$`)
	hexRe     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
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
		BodyEncoding:    firstNonEmpty(wire.BodyEncoding, "base64"),
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
	pathPart := strings.SplitN(path, "?", 2)[0]
	parts := strings.Split(pathPart, "/")
	params := []PathParam{}
	nameCounts := map[string]int{}
	previousStatic := ""
	for i, part := range parts {
		if part == "" {
			continue
		}
		if IsDynamicSegment(part) {
			prefix := pathParamPrefix(previousStatic)
			baseName := "id"
			if prefix != "id" {
				baseName = prefix + "Id"
			}
			name := dedupeParamName(baseName, nameCounts)
			parts[i] = "{" + name + "}"
			params = append(params, PathParam{Name: name, ObservedValue: part})
			continue
		}
		previousStatic = part
	}
	normalized := strings.Join(parts, "/")
	if normalized == "" {
		normalized = "/"
	}
	return normalized, params
}

func IsDynamicSegment(part string) bool {
	return uuidRe.MatchString(part) || numericRe.MatchString(part) || hexRe.MatchString(part)
}

func pathParamPrefix(previousStatic string) string {
	if previousStatic == "" {
		return "id"
	}
	prefix := SingularizeSegment(previousStatic)
	if len(prefix) < 3 {
		prefix = previousStatic
	}
	return CamelName(prefix)
}

func dedupeParamName(base string, counts map[string]int) string {
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

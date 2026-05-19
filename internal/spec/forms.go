package spec

import (
	"net/url"
	"regexp"
	"strings"
)

var multipartNameRe = regexp.MustCompile(`name="([^"]+)"`)
var multipartFilenameRe = regexp.MustCompile(`filename="[^"]*"`)

func ParseFormURLEncoded(body []byte) map[string]any {
	if len(body) == 0 {
		return nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || len(values) == 0 {
		return nil
	}
	out := map[string]any{}
	for key, vals := range values {
		if len(vals) == 0 {
			out[key] = ""
		} else {
			out[key] = vals[0]
		}
	}
	return out
}

func ParseMultipart(body []byte, contentType string) map[string]any {
	if len(body) == 0 {
		return nil
	}
	boundary := ""
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "boundary=") {
			boundary = strings.TrimPrefix(part, "boundary=")
			break
		}
	}
	if boundary == "" {
		return nil
	}
	text := string(body)
	out := map[string]any{}
	for _, segment := range strings.Split(text, "--"+boundary) {
		nameMatch := multipartNameRe.FindStringSubmatch(segment)
		if len(nameMatch) < 2 {
			continue
		}
		name := nameMatch[1]
		if multipartFilenameRe.MatchString(segment) {
			out[name] = fileSentinel
			continue
		}
		value := ""
		if parts := strings.SplitN(segment, "\r\n\r\n", 2); len(parts) == 2 {
			value = parts[1]
		} else if parts := strings.SplitN(segment, "\n\n", 2); len(parts) == 2 {
			value = parts[1]
		}
		value = strings.TrimSpace(strings.TrimSuffix(value, "-"))
		out[name] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

package adapter

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/4LAU/apisniff-go/internal/model"
)

type burpItems struct {
	Items []burpItem `xml:"item"`
}

type burpItem struct {
	Method   string  `xml:"method"`
	URL      string  `xml:"url"`
	Status   string  `xml:"status"`
	Request  burpRaw `xml:"request"`
	Response burpRaw `xml:"response"`
}

type burpRaw struct {
	Base64 string `xml:"base64,attr"`
	Text   string `xml:",chardata"`
}

func LoadBurp(path string) ([]model.CapturedFlow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	var root burpItems
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	flows := make([]model.CapturedFlow, 0, len(root.Items))
	for _, item := range root.Items {
		parsed, err := url.Parse(strings.TrimSpace(item.URL))
		if err != nil || !isAbsoluteRequestURL(parsed) {
			continue
		}
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		status, _ := strconv.Atoi(strings.TrimSpace(item.Status))
		reqHeaders, reqBody := splitHTTPMessage(decodeBurpRaw(item.Request))
		respHeaders, respBody := splitHTTPMessage(decodeBurpRaw(item.Response))
		flows = append(flows, model.CapturedFlow{
			Method:          firstNonEmpty(strings.TrimSpace(item.Method), "GET"),
			Host:            parsed.Hostname(),
			Path:            path,
			URL:             strings.TrimSpace(item.URL),
			RequestHeaders:  reqHeaders,
			RequestBody:     reqBody,
			ResponseStatus:  status,
			ResponseHeaders: respHeaders,
			ResponseBody:    respBody,
			BodyEncoding:    "base64",
			Tags:            []string{},
		})
	}
	return flows, nil
}

func decodeBurpRaw(raw burpRaw) []byte {
	text := strings.TrimSpace(raw.Text)
	if raw.Base64 == "true" {
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			return decoded
		}
	}
	return []byte(text)
}

func splitHTTPMessage(raw []byte) (map[string]string, []byte) {
	headerBytes := raw
	body := []byte{}
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		headerBytes = raw[:idx]
		body = raw[idx+4:]
	} else if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		headerBytes = raw[:idx]
		body = raw[idx+2:]
	}
	text := strings.ReplaceAll(string(headerBytes), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) <= 1 {
		return map[string]string{}, body
	}
	grouped := map[string][]string{}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		grouped[strings.ToLower(strings.TrimSpace(key))] = append(grouped[strings.ToLower(strings.TrimSpace(key))], strings.TrimSpace(value))
	}
	return joinHeaderValues(grouped), body
}

package adapter

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/4LAU/apisniff-go/internal/model"
)

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
}

type harRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Headers  []harHeader `json:"headers"`
	PostData *struct {
		Text string `json:"text"`
	} `json:"postData"`
}

type harResponse struct {
	Status  int         `json:"status"`
	Headers []harHeader `json:"headers"`
	Content struct {
		Text     string `json:"text"`
		Encoding string `json:"encoding"`
	} `json:"content"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func LoadHAR(path string) ([]model.CapturedFlow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, err
	}
	flows := make([]model.CapturedFlow, 0, len(har.Log.Entries))
	for _, entry := range har.Log.Entries {
		parsed, _ := url.Parse(entry.Request.URL)
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		reqBody := []byte{}
		if entry.Request.PostData != nil {
			reqBody = []byte(entry.Request.PostData.Text)
		}
		respBody := []byte(entry.Response.Content.Text)
		if strings.EqualFold(entry.Response.Content.Encoding, "base64") && entry.Response.Content.Text != "" {
			if decoded, err := base64.StdEncoding.DecodeString(entry.Response.Content.Text); err == nil {
				respBody = decoded
			}
		}
		flows = append(flows, model.CapturedFlow{
			Method:          firstNonEmpty(entry.Request.Method, "GET"),
			Host:            parsed.Hostname(),
			Path:            path,
			URL:             entry.Request.URL,
			RequestHeaders:  parseHARHeaders(entry.Request.Headers),
			RequestBody:     reqBody,
			ResponseStatus:  entry.Response.Status,
			ResponseHeaders: parseHARHeaders(entry.Response.Headers),
			ResponseBody:    respBody,
			BodyEncoding:    "base64",
			Tags:            []string{},
			Timestamp:       parseHARTimestamp(entry.StartedDateTime),
		})
	}
	return flows, nil
}

func parseHARHeaders(headers []harHeader) map[string]string {
	grouped := map[string][]string{}
	for _, header := range headers {
		if header.Name == "" {
			continue
		}
		key := strings.ToLower(header.Name)
		grouped[key] = append(grouped[key], header.Value)
	}
	return joinHeaderValues(grouped)
}

func parseHARTimestamp(raw string) float64 {
	if raw == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

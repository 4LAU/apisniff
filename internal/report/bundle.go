package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/4LAU/apisniff/internal/finalize"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/spec"
)

const (
	graphQLResultsFile = "graphql.json"
	graphQLFetchLimit  = 10 << 20
)

const graphQLIntrospectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
`

type GraphQLFetchResult struct {
	Endpoint      string          `json:"endpoint"`
	Status        int             `json:"status,omitempty"`
	Introspection bool            `json:"introspection"`
	Schema        json.RawMessage `json:"schema,omitempty"`
	Error         string          `json:"error,omitempty"`
}

// WriteBundle writes the offline analyze bundle shape used by capture bundles.
// It returns the GraphQL catalog summary so callers can surface it (counts are
// all zero when no GraphQL operations were observed).
func WriteBundle(dir string, flows []model.CapturedFlow, session model.SessionStats) (finalize.Summary, error) {
	if dir == "" {
		return finalize.Summary{}, fmt.Errorf("output dir is required")
	}
	if err := ensurePrivateDir(dir); err != nil {
		return finalize.Summary{}, err
	}
	if err := writeJSONFile(filepath.Join(dir, "session.json"), session); err != nil {
		return finalize.Summary{}, err
	}
	if err := writeFlowsJSONL(filepath.Join(dir, "flows.jsonl"), flows); err != nil {
		return finalize.Summary{}, err
	}
	inventory := BuildInventory(flows, session.Domain)
	// Imported flows carry no category tags; classify so the report shows
	// real categories instead of "uncategorized".
	inventory.Categories = spec.BuildSurfaceInventory(flows, session.Domain).Categories
	if err := writePrivateFile(filepath.Join(dir, "report.md"), Markdown(inventory)); err != nil {
		return finalize.Summary{}, err
	}
	// Co-locate the OpenAPI spec + the private GraphQL catalog (raw URLs/variables —
	// never shareable). dir is already a 0o600 private bundle.
	summary, err := finalize.FinalizeBundle(dir, flows, session.Domain)
	if err != nil {
		return finalize.Summary{}, err
	}
	return summary, nil
}

func FetchGraphQLSchemas(ctx context.Context, flows []model.CapturedFlow) ([]GraphQLFetchResult, error) {
	endpoints := detectGraphQLEndpoints(flows)
	client := &http.Client{Timeout: 10 * time.Second}
	results := make([]GraphQLFetchResult, 0, len(endpoints))
	for _, endpoint := range endpoints {
		result := fetchGraphQLEndpoint(ctx, client, endpoint)
		results = append(results, result)
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
	}
	return results, nil
}

func WriteGraphQLResults(dir string, results []GraphQLFetchResult) error {
	if dir == "" {
		return fmt.Errorf("output dir is required")
	}
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	endpoints := make([]string, 0, len(results))
	introspection := false
	for _, result := range results {
		endpoints = append(endpoints, result.Endpoint)
		introspection = introspection || result.Introspection
	}
	payload := struct {
		model.GraphQLResult
		Results []GraphQLFetchResult `json:"results"`
	}{
		GraphQLResult: model.GraphQLResult{
			Endpoints:     endpoints,
			Introspection: introspection,
		},
		Results: results,
	}
	return writeJSONFile(filepath.Join(dir, graphQLResultsFile), payload)
}

func writeFlowsJSONL(path string, flows []model.CapturedFlow) error {
	var buf bytes.Buffer
	for _, flow := range flows {
		line, err := flow.ToJSONL()
		if err != nil {
			return err
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	return writePrivateFile(path, buf.Bytes())
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, append(data, '\n'))
}

func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func detectGraphQLEndpoints(flows []model.CapturedFlow) []string {
	seen := map[string]struct{}{}
	for _, flow := range flows {
		if !isGraphQLCandidate(flow) {
			continue
		}
		endpoint := endpointURL(flow)
		if endpoint != "" {
			seen[endpoint] = struct{}{}
		}
	}
	endpoints := make([]string, 0, len(seen))
	for endpoint := range seen {
		endpoints = append(endpoints, endpoint)
	}
	sort.Strings(endpoints)
	return endpoints
}

func isGraphQLCandidate(flow model.CapturedFlow) bool {
	path := strings.ToLower(flow.Path)
	if path == "" && flow.URL != "" {
		if parsed, err := url.Parse(flow.URL); err == nil {
			path = strings.ToLower(parsed.Path)
		}
	}
	if strings.Contains(path, "/graphql") {
		return true
	}
	for _, headers := range []map[string]string{flow.RequestHeaders, flow.ResponseHeaders} {
		if strings.Contains(strings.ToLower(model.GetHeader(headers, "content-type")), "graphql") {
			return true
		}
	}
	return hasGraphQLQueryBody(flow.RequestBody)
}

func hasGraphQLQueryBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var payload struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	query := strings.TrimSpace(payload.Query)
	return strings.Contains(query, "{") || strings.Contains(strings.ToLower(query), "query ") || strings.Contains(strings.ToLower(query), "mutation ")
}

func endpointURL(flow model.CapturedFlow) string {
	raw := strings.TrimSpace(flow.URL)
	if raw == "" && flow.Host != "" && flow.Path != "" {
		raw = "https://" + flow.Host + flow.Path
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Host == "" && flow.Host != "" {
		if parsed.Path == "" && flow.Path != "" {
			if fallback, err := url.Parse(flow.Path); err == nil {
				parsed = fallback
			}
		}
		parsed.Scheme = "https"
		parsed.Host = flow.Host
	}
	if parsed.Host == "" {
		return ""
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func fetchGraphQLEndpoint(ctx context.Context, client *http.Client, endpoint string) GraphQLFetchResult {
	result := GraphQLFetchResult{Endpoint: endpoint}
	payload, err := json.Marshal(map[string]string{"query": graphQLIntrospectionQuery})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("accept", "application/graphql-response+json, application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", "apisniff-go")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Status = resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, graphQLFetchLimit+1))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if len(body) > graphQLFetchLimit {
		result.Error = fmt.Sprintf("response exceeds %d bytes", graphQLFetchLimit)
		return result
	}
	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("unexpected status: %d", resp.StatusCode)
		return result
	}
	var decoded struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		result.Error = err.Error()
		return result
	}
	schema, ok := decoded.Data["__schema"]
	if !ok || string(schema) == "null" {
		result.Error = "missing data.__schema"
		return result
	}
	result.Introspection = true
	result.Schema = append(json.RawMessage(nil), body...)
	return result
}

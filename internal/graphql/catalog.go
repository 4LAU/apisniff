package graphql

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/4LAU/apisniff/internal/jsonschema"
	"github.com/4LAU/apisniff/internal/model"
)

// catalogSchemaVersion is the on-disk format version of the GraphQL catalog.
const catalogSchemaVersion = 1

const (
	catalogJSONName = "graphql-operations.json"
	catalogSDLName  = "operations.graphql"
)

// requestTruncationTags mark a flow whose REQUEST body is not authoritative.
var requestTruncationTags = []string{"request_body_truncated", "request_body_incomplete", "body_stripped"}

// responseTruncationTags mark a flow whose RESPONSE body is not authoritative.
var responseTruncationTags = []string{"response_body_truncated", "response_body_incomplete", "body_stripped"}

// Catalog is the deduplicated set of GraphQL operations observed across flows.
// It carries RAW endpoint URLs and RAW variable values (private use only — never
// emit publicly); write it only into a private capture bundle, never a share.
type Catalog struct {
	SchemaVersion  int         `json:"schema_version"`
	OperationCount int         `json:"operation_count"`
	FlowCount      int         `json:"flow_count"`
	Endpoints      []string    `json:"endpoints"`
	Operations     []CatalogOp `json:"operations"`
}

// CatalogOp is one deduplicated GraphQL operation with merged schemas.
type CatalogOp struct {
	OperationName    string          `json:"operation_name"`
	OperationType    string          `json:"operation_type"`
	Endpoint         string          `json:"endpoint"`
	Method           string          `json:"method"`
	Source           string          `json:"source"` // captured-query | persisted-hash
	Query            *string         `json:"query"`
	PersistedHash    *string         `json:"persisted_hash"`
	VariablesExample json.RawMessage `json:"variables_example,omitempty"`
	VariablesSchema  map[string]any  `json:"variables_schema,omitempty"`
	ResponseSchema   map[string]any  `json:"response_schema,omitempty"`
	ObservedCount    int             `json:"observed_count"`
	StatusCodes      []int           `json:"status_codes"`
	Quality          string          `json:"quality"` // complete | partial
	HashMismatch     bool            `json:"hash_mismatch,omitempty"`
}

// contribution is one Operation observed in one flow, with authoritativeness
// resolved from the flow's tags and body validity.
type contribution struct {
	op                Operation
	discriminatorHash string
	hashMismatch      bool
	requestOK         bool // request body authoritative (variables/query trustworthy)
	responseOK        bool // response body authoritative
}

// group accumulates contributions sharing a composite identity key.
type group struct {
	key     string
	members []contribution
}

// BuildCatalog deduplicates the GraphQL operations across flows into a Catalog.
// Identical input yields identical output (deterministic ordering and merging).
func BuildCatalog(flows []model.CapturedFlow) Catalog {
	groups := map[string]*group{}
	order := []string{}
	endpoints := map[string]struct{}{}
	flowCount := 0
	for _, flow := range flows {
		contributed := false
		reqOK, respOK := flowBodyAuthoritative(flow)
		for _, op := range ExtractGraphQLOperations(flow) {
			contributed = true
			c := newContribution(op, reqOK, respOK)
			endpoints[op.Endpoint] = struct{}{}
			key := groupKey(op, c.discriminatorHash)
			if groups[key] == nil {
				groups[key] = &group{key: key}
				order = append(order, key)
			}
			groups[key].members = append(groups[key].members, c)
		}
		if contributed {
			flowCount++
		}
	}
	ops := make([]CatalogOp, 0, len(order))
	for _, key := range order {
		ops = append(ops, aggregateGroup(groups[key]))
	}
	sortCatalogOps(ops)
	return Catalog{
		SchemaVersion:  catalogSchemaVersion,
		OperationCount: len(ops),
		FlowCount:      flowCount,
		Endpoints:      sortedKeys(endpoints),
		Operations:     ops,
	}
}

// newContribution resolves the discriminator hash, APQ consistency, and
// per-body authoritativeness for one observed Operation.
func newContribution(op Operation, reqOK, respOK bool) contribution {
	c := contribution{op: op, requestOK: reqOK, responseOK: respOK}
	if op.Query != "" && op.PersistedHash != "" {
		if sha256hex(op.Query) == op.PersistedHash {
			c.discriminatorHash = op.PersistedHash
		} else {
			c.discriminatorHash = sha256hex(strings.TrimSpace(op.Query))
			c.hashMismatch = true
		}
		return c
	}
	if op.PersistedHash != "" {
		c.discriminatorHash = op.PersistedHash
		return c
	}
	c.discriminatorHash = sha256hex(strings.TrimSpace(op.Query))
	return c
}

// groupKey is the composite identity {endpoint, method, name, discriminator}.
// operationName is never the sole key.
func groupKey(op Operation, discriminator string) string {
	return strings.Join([]string{op.Endpoint, op.Method, op.OperationName, discriminator}, "\x00")
}

// aggregateGroup merges a group's contributions into one CatalogOp.
func aggregateGroup(g *group) CatalogOp {
	first := g.members[0].op
	out := CatalogOp{
		OperationName: first.OperationName,
		OperationType: first.OperationType,
		Endpoint:      first.Endpoint,
		Method:        first.Method,
		ObservedCount: len(g.members),
		Quality:       "complete",
		HashMismatch:  g.members[0].hashMismatch,
	}
	out.Source = groupSource(g)
	out.StatusCodes = collectStatuses(g)
	if out.Source == "persisted-hash" {
		hash := first.PersistedHash
		out.PersistedHash = &hash
	} else {
		applyQueryAggregates(&out, g)
	}
	if first.PersistedHash != "" && out.PersistedHash == nil {
		// captured-query group that also carries a hash (e.g. APQ mismatch).
		hash := first.PersistedHash
		out.PersistedHash = &hash
	}
	aggregateSchemas(&out, g)
	if !groupComplete(g) {
		out.Quality = "partial"
	}
	return out
}

// groupSource is "persisted-hash" only when every contribution is hash-only.
func groupSource(g *group) string {
	for _, c := range g.members {
		if !(c.op.Query == "" && c.op.PersistedHash != "") {
			return "captured-query"
		}
	}
	return "persisted-hash"
}

// applyQueryAggregates sets the canonical query (longest, lexical tie-break)
// and the lexically-first complete variables example.
func applyQueryAggregates(out *CatalogOp, g *group) {
	query := canonicalQuery(g)
	out.Query = &query
	out.VariablesExample = firstCompleteVariables(g)
}

// canonicalQuery returns the longest observed query text, lexical tie-break,
// over authoritative request contributions only (IR-4): a non-authoritative
// request body must not donate its possibly-incomplete query text.
func canonicalQuery(g *group) string {
	best := ""
	for _, c := range g.members {
		if !c.requestOK {
			continue
		}
		q := c.op.Query
		if q == "" {
			continue
		}
		if len(q) > len(best) || (len(q) == len(best) && q < best) {
			best = q
		}
	}
	return best
}

// firstCompleteVariables returns the lexically-first raw variables JSON among
// authoritative (complete) request contributions.
func firstCompleteVariables(g *group) json.RawMessage {
	best := ""
	found := false
	for _, c := range g.members {
		if !c.requestOK || len(c.op.Variables) == 0 {
			continue
		}
		v := string(c.op.Variables)
		if !found || v < best {
			best = v
			found = true
		}
	}
	if !found {
		return nil
	}
	return json.RawMessage(best)
}

// aggregateSchemas merges variable and response schemas over authoritative
// contributions.
func aggregateSchemas(out *CatalogOp, g *group) {
	var varsSchema, respSchema map[string]any
	for _, c := range g.members {
		if c.requestOK && len(c.op.Variables) > 0 {
			if s := inferBodySchema(c.op.Variables); s != nil {
				varsSchema = jsonschema.MergeSchemas(varsSchema, s)
			}
		}
		if c.responseOK && len(c.op.ResponseBody) > 0 {
			if s := inferBodySchema(c.op.ResponseBody); s != nil {
				respSchema = jsonschema.MergeSchemas(respSchema, s)
			}
		}
	}
	out.VariablesSchema = varsSchema
	out.ResponseSchema = respSchema
}

// inferBodySchema parses a JSON body and infers its schema, or nil on failure.
func inferBodySchema(body []byte) map[string]any {
	value := jsonschema.ParseJSONBody(body)
	if value == nil {
		return nil
	}
	return jsonschema.InferSchema(value, false, "")
}

// groupComplete reports whether every contribution to the group was fully
// authoritative (both request and response bodies trustworthy).
func groupComplete(g *group) bool {
	for _, c := range g.members {
		if !c.requestOK || !c.responseOK {
			return false
		}
	}
	return true
}

// collectStatuses returns the sorted distinct status codes in the group.
func collectStatuses(g *group) []int {
	seen := map[int]struct{}{}
	for _, c := range g.members {
		seen[c.op.Status] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Ints(out)
	return out
}

// flowBodyAuthoritative reports whether a flow's request and response bodies
// are authoritative under IR-4. A body is non-authoritative when a truncation
// tag marks it incomplete, OR — for the response, and likewise the request —
// when the body is present but does not parse as valid complete JSON. The
// JSON-validity clause flips Quality to partial even with no tag present.
func flowBodyAuthoritative(flow model.CapturedFlow) (reqOK, respOK bool) {
	reqOK = !hasAnyTag(flow.Tags, requestTruncationTags) && bodyJSONComplete(flow.RequestBody)
	respOK = !hasAnyTag(flow.Tags, responseTruncationTags) && bodyJSONComplete(flow.ResponseBody)
	return reqOK, respOK
}

// bodyJSONComplete reports whether a body is authoritative on JSON grounds: an
// absent (empty) body is vacuously authoritative; a present body must be valid
// complete JSON. A present-but-invalid body (e.g. `{"data":{"x":`) is not.
func bodyJSONComplete(body []byte) bool {
	return len(body) == 0 || json.Valid(body)
}

// hasAnyTag reports whether tags contains any of the given markers.
func hasAnyTag(tags, markers []string) bool {
	for _, t := range tags {
		for _, m := range markers {
			if t == m {
				return true
			}
		}
	}
	return false
}

// sortCatalogOps orders operations by (OperationName, Endpoint, discriminator).
func sortCatalogOps(ops []CatalogOp) {
	sort.SliceStable(ops, func(i, j int) bool {
		if ops[i].OperationName != ops[j].OperationName {
			return ops[i].OperationName < ops[j].OperationName
		}
		if ops[i].Endpoint != ops[j].Endpoint {
			return ops[i].Endpoint < ops[j].Endpoint
		}
		return opDiscriminator(ops[i]) < opDiscriminator(ops[j])
	})
}

// opDiscriminator returns the discriminator hash used for tie-break ordering.
func opDiscriminator(op CatalogOp) string {
	if op.PersistedHash != nil && op.Query == nil {
		return *op.PersistedHash
	}
	if op.Query != nil {
		return sha256hex(strings.TrimSpace(*op.Query))
	}
	if op.PersistedHash != nil {
		return *op.PersistedHash
	}
	return ""
}

// sortedKeys returns the sorted keys of a string set.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sha256hex returns the lowercase hex SHA-256 of s.
func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// WriteCatalog writes the catalog JSON and SDL to dir, or removes stale files
// when the catalog is empty (IR-5). The artifacts carry RAW URLs and RAW
// variable values (private use only — never emit publicly); dir MUST be a
// private capture bundle, never a share output directory.
func WriteCatalog(dir string, cat Catalog) error {
	if cat.OperationCount == 0 {
		return removeStale(dir)
	}
	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, catalogJSONName), data); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, catalogSDLName), []byte(buildSDL(cat)))
}

// removeStale deletes any pre-existing catalog files, ignoring missing ones.
func removeStale(dir string) error {
	for _, name := range []string{catalogJSONName, catalogSDLName} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// atomicWrite writes data to a sibling temp file (0o600) then renames it.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// buildSDL renders the operations.graphql document: only captured-query named
// operations, with colliding document names suffixed by hash prefix.
func buildSDL(cat Catalog) string {
	included := sdlOps(cat)
	names := documentNames(included)
	docs := make([]string, 0, len(included))
	for i, op := range included {
		docs = append(docs, renderDocument(names[i], *op.Query))
	}
	return strings.Join(docs, "\n")
}

// sdlOps returns the catalog ops eligible for the SDL document: captured-query
// with a non-empty operation name and actual (non-blank) query text. An op whose
// canonical query is empty (every contribution had a non-authoritative request,
// IR-4) is omitted so the SDL file never carries an empty/dangling document; its
// identity still lives in the JSON catalog.
func sdlOps(cat Catalog) []CatalogOp {
	out := []CatalogOp{}
	for _, op := range cat.Operations {
		if op.Source == "captured-query" && op.OperationName != "" &&
			op.Query != nil && strings.TrimSpace(*op.Query) != "" {
			out = append(out, op)
		}
	}
	return out
}

// documentNames returns the document name for each included op, suffixing any
// name shared by two or more ops with the first 8 chars of its discriminator.
func documentNames(ops []CatalogOp) []string {
	counts := map[string]int{}
	for _, op := range ops {
		counts[op.OperationName]++
	}
	names := make([]string, len(ops))
	for i, op := range ops {
		if counts[op.OperationName] > 1 {
			names[i] = op.OperationName + "_" + shortHash(opDiscriminator(op))
		} else {
			names[i] = op.OperationName
		}
	}
	return names
}

// shortHash returns the first 8 characters of a discriminator hash.
func shortHash(h string) string {
	if len(h) >= 8 {
		return h[:8]
	}
	return h
}

// renderDocument renders one query with its (possibly suffixed) document name
// substituted into the leading operation declaration.
func renderDocument(name, query string) string {
	q := strings.TrimSpace(query)
	loc := declRe.FindStringSubmatchIndex(q)
	if loc == nil {
		return q + "\n"
	}
	// loc[4]:loc[5] spans the original operation name in the declaration.
	return q[:loc[4]] + name + q[loc[5]:] + "\n"
}

package replay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/model"
)

func replayFlow(method, rawURL, path string, status int, body []byte) model.CapturedFlow {
	return model.CapturedFlow{
		Method:          method,
		Host:            "example.com",
		Path:            path,
		URL:             rawURL,
		RequestHeaders:  map[string]string{"Connection": "keep-alive", "X-Trace": "1"},
		ResponseStatus:  status,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    body,
		BodyEncoding:    "base64",
		Timestamp:       1,
	}
}

func TestBuildRequestRemovesHopByHopAndAddsCookies(t *testing.T) {
	flow := replayFlow("GET", "https://api.example.com/v1/users?q=1", "/v1/users?q=1", 200, nil)
	flow.Host = "api.example.com:443"
	req, err := buildRequest(context.Background(), flow, map[string]string{"Authorization": "Bearer x"}, []Cookie{{Domain: ".example.com", Name: "sid", Value: "abc"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.RawQuery != "q=1" {
		t.Fatalf("query not preserved: %s", req.URL.String())
	}
	if req.Header.Get("connection") != "" {
		t.Fatalf("connection header was not stripped")
	}
	if req.Header.Get("authorization") != "Bearer x" {
		t.Fatalf("authorization header = %q", req.Header.Get("authorization"))
	}
	if req.Header.Get("cookie") != "sid=abc" {
		t.Fatalf("cookie header = %q", req.Header.Get("cookie"))
	}
}

func TestBuildRequestSplitsProxyJoinedMultiValueHeaders(t *testing.T) {
	flow := replayFlow("GET", "https://api.example.com/v1/users", "/v1/users", 200, nil)
	flow.Host = "api.example.com"
	flow.RequestHeaders = map[string]string{"accept": "application/json\ntext/plain"}
	req, err := buildRequest(context.Background(), flow, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	got := req.Header.Values("accept")
	want := []string{"application/json", "text/plain"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("accept values = %q, want %q", got, want)
	}
	// A raw newline in a header value makes http.Client.Do reject the
	// whole request, so the split must leave no newlines behind.
	for _, v := range got {
		if strings.Contains(v, "\n") {
			t.Fatalf("header value still contains newline: %q", v)
		}
	}
}

func TestBuildRequestStripsCapturedAuthHeadersByDefault(t *testing.T) {
	flow := replayFlow("GET", "https://api.example.com/v1/users", "/v1/users", 200, nil)
	flow.Host = "api.example.com"
	flow.RequestHeaders = map[string]string{
		"Authorization":      "Bearer captured",
		"Cookie":             "sid=captured",
		"X-Auth-Token":       "auth-token",
		"X-Px-Authorization": "px-token",
		"X-Trace":            "1",
	}
	req, err := buildRequest(context.Background(), flow, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"authorization", "cookie", "x-auth-token", "x-px-authorization"} {
		if req.Header.Get(header) != "" {
			t.Fatalf("%s was forwarded: %#v", header, req.Header)
		}
	}
	if req.Header.Get("x-trace") != "1" {
		t.Fatalf("non-auth header missing: %#v", req.Header)
	}
}

func TestBuildRequestForwardAuthKeepsCapturedAuthHeaders(t *testing.T) {
	flow := replayFlow("GET", "https://api.example.com/v1/users", "/v1/users", 200, nil)
	flow.Host = "api.example.com"
	flow.RequestHeaders = map[string]string{
		"Authorization": "Bearer captured",
		"Cookie":        "sid=captured",
	}
	req, err := buildRequest(context.Background(), flow, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("authorization") != "Bearer captured" || req.Header.Get("cookie") != "sid=captured" {
		t.Fatalf("captured auth headers not forwarded: %#v", req.Header)
	}
}

func TestRunDryRunSummarizesSafeAndUnsafe(t *testing.T) {
	dir := t.TempDir()
	flowsPath := filepath.Join(dir, "flows.jsonl")
	writeFlows(t, flowsPath, []model.CapturedFlow{
		replayFlow("GET", "https://example.com/api/users", "/api/users", 200, []byte(`{"ok":true}`)),
		replayFlow("POST", "https://example.com/api/users", "/api/users", 201, []byte(`{"ok":true}`)),
	})

	summary, err := Run(context.Background(), Options{BundleOrDomain: flowsPath, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Mode != "dry_run" || summary.Summary["safe"] != 1 || summary.Summary["unsafe"] != 1 || summary.Summary["total"] != 2 {
		t.Fatalf("summary = %#v", summary)
	}
	if strings.Join(summary.Endpoints, ",") != "GET /api/users,POST /api/users" {
		t.Fatalf("endpoints = %#v", summary.Endpoints)
	}
}

func TestRunReplaysHermeticGETAndPOSTWhenUnsafeIncluded(t *testing.T) {
	var sawGET atomic.Bool
	var sawPOST atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/get":
			sawGET.Store(true)
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":false,"id":2}`))
		case "POST /api/post":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read POST body: %v", err)
			}
			if string(body) != `{"name":"alice"}` {
				t.Errorf("POST body = %q", body)
			}
			sawPOST.Store(true)
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"created":false,"id":2}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	flowsPath := filepath.Join(dir, "flows.jsonl")
	writeFlows(t, flowsPath, []model.CapturedFlow{
		serverFlow(server.URL, "GET", "/api/get", http.StatusOK, nil, []byte(`{"ok":true,"id":1}`), nil),
		serverFlow(server.URL, "POST", "/api/post", http.StatusCreated, []byte(`{"name":"alice"}`), []byte(`{"created":true,"id":1}`), map[string]string{"Content-Type": "application/json"}),
	})

	summary, err := Run(context.Background(), Options{BundleOrDomain: flowsPath, IncludeUnsafe: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Summary["match"] != 2 || len(summary.Results) != 2 {
		t.Fatalf("summary = %#v", summary)
	}
	if !sawGET.Load() || !sawPOST.Load() {
		t.Fatalf("server saw GET=%v POST=%v", sawGET.Load(), sawPOST.Load())
	}
}

func TestReplayOneStripsCapturedAuthHeadersBeforeNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("authorization"); got != "" {
			t.Errorf("authorization forwarded: %q", got)
		}
		if got := r.Header.Get("cookie"); got != "" {
			t.Errorf("cookie forwarded: %q", got)
		}
		if got := r.Header.Get("x-api-key"); got != "" {
			t.Errorf("x-api-key forwarded: %q", got)
		}
		if got := r.Header.Get("x-trace"); got != "1" {
			t.Errorf("x-trace = %q, want 1", got)
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":false}`))
	}))
	defer server.Close()

	flow := serverFlow(server.URL, "GET", "/api/auth", http.StatusOK, nil, []byte(`{"ok":true}`), map[string]string{
		"Authorization": "Bearer captured",
		"Cookie":        "sid=captured",
		"X-Api-Key":     "captured-key",
		"X-Trace":       "1",
	})

	result := ReplayOne(context.Background(), server.Client(), flow, Options{}, nil)
	if result.Category != "match" {
		t.Fatalf("result = %#v", result)
	}
}

func TestReplayOneStripsQueryCredentialsBeforeNetwork(t *testing.T) {
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	path := "/api/data?api_key=sk1&access_token=at1&client_secret=cs1&signature=sg1&token=t1&q=ok&page=2"
	flow := serverFlow(server.URL, "GET", path, http.StatusOK, nil, []byte(`{"ok":true}`), nil)

	ReplayOne(context.Background(), server.Client(), flow, Options{}, nil)
	for _, credential := range []string{"api_key", "access_token", "client_secret", "signature", "token"} {
		if gotQuery.Has(credential) {
			t.Errorf("credential query param %q forwarded: %q", credential, gotQuery.Get(credential))
		}
	}
	if gotQuery.Get("q") != "ok" || gotQuery.Get("page") != "2" {
		t.Fatalf("non-credential params mangled: %v", gotQuery)
	}

	ReplayOne(context.Background(), server.Client(), flow, Options{ForwardAuth: true}, nil)
	if gotQuery.Get("api_key") != "sk1" || gotQuery.Get("access_token") != "at1" {
		t.Fatalf("--forward-auth did not forward query credentials: %v", gotQuery)
	}
}

func TestRunAppliesGlobFilterBeforeReplay(t *testing.T) {
	var users atomic.Int32
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users":
			users.Add(1)
			w.Write([]byte(`{"ok":true}`))
		case "/api/posts":
			posts.Add(1)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	flowsPath := filepath.Join(dir, "flows.jsonl")
	writeFlows(t, flowsPath, []model.CapturedFlow{
		serverFlow(server.URL, "GET", "/api/users", http.StatusOK, nil, []byte(`{"ok":true}`), nil),
		serverFlow(server.URL, "GET", "/api/posts", http.StatusOK, nil, []byte(`{"ok":true}`), nil),
	})

	summary, err := Run(context.Background(), Options{BundleOrDomain: flowsPath, Filter: "/api/users*", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Results) != 1 || summary.Results[0].Path != "/api/users" {
		t.Fatalf("results = %#v", summary.Results)
	}
	if users.Load() != 1 || posts.Load() != 0 {
		t.Fatalf("users requests = %d, posts requests = %d", users.Load(), posts.Load())
	}
}

func TestRunRejectsInvalidFilterPattern(t *testing.T) {
	dir := t.TempDir()
	flowsPath := filepath.Join(dir, "flows.jsonl")
	writeFlows(t, flowsPath, []model.CapturedFlow{
		serverFlow("http://localhost", "GET", "/api", http.StatusOK, nil, nil, nil),
	})

	_, err := Run(context.Background(), Options{BundleOrDomain: flowsPath, Filter: "[", Timeout: time.Second})
	if err == nil {
		t.Fatal("expected error for invalid filter pattern")
	}
	if !strings.Contains(err.Error(), "invalid filter pattern") {
		t.Fatalf("error = %q, want 'invalid filter pattern'", err.Error())
	}
}

func TestReplayOneDetectsMatchDriftAuthExpiredAndBlocked(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		originalStatus int
		originalBody   []byte
		requestHeaders map[string]string
		replayStatus   int
		replayBody     []byte
		wantCategory   string
		wantBodyMatch  bool
	}{
		{
			name:           "match",
			originalStatus: http.StatusOK,
			originalBody:   []byte(`{"id":1,"name":"alice"}`),
			replayStatus:   http.StatusOK,
			replayBody:     []byte(`{"id":2,"name":"bob"}`),
			wantCategory:   "match",
			wantBodyMatch:  true,
		},
		{
			name:           "drift",
			originalStatus: http.StatusOK,
			originalBody:   []byte(`{"id":1,"name":"alice"}`),
			replayStatus:   http.StatusOK,
			replayBody:     []byte(`{"id":2,"name":"bob","extra":true}`),
			wantCategory:   "drift",
			wantBodyMatch:  false,
		},
		{
			name:           "auth expired",
			originalStatus: http.StatusOK,
			originalBody:   []byte(`{"ok":true}`),
			requestHeaders: map[string]string{"Authorization": "Bearer stale"},
			replayStatus:   http.StatusUnauthorized,
			replayBody:     []byte(`{"error":"unauthorized"}`),
			wantCategory:   "auth_expired",
			wantBodyMatch:  false,
		},
		{
			// Auth captured only in the query string is stripped before
			// replay; the resulting 401 is expired credentials, not blocking.
			name:           "auth expired via stripped query credential",
			path:           "/api/me?access_token=stale",
			originalStatus: http.StatusOK,
			originalBody:   []byte(`{"ok":true}`),
			replayStatus:   http.StatusUnauthorized,
			replayBody:     []byte(`{"error":"unauthorized"}`),
			wantCategory:   "auth_expired",
			wantBodyMatch:  false,
		},
		{
			name:           "blocked",
			originalStatus: http.StatusOK,
			originalBody:   []byte(`{"ok":true}`),
			replayStatus:   http.StatusTooManyRequests,
			replayBody:     []byte(`rate limited`),
			wantCategory:   "blocked",
			wantBodyMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.replayStatus)
				w.Write(tt.replayBody)
			}))
			defer server.Close()

			path := tt.path
			if path == "" {
				path = "/api/test"
			}
			flow := serverFlow(server.URL, "GET", path, tt.originalStatus, nil, tt.originalBody, tt.requestHeaders)
			result := ReplayOne(context.Background(), server.Client(), flow, Options{}, nil)
			if result.Category != tt.wantCategory {
				t.Fatalf("category = %q, want %q; result = %#v", result.Category, tt.wantCategory, result)
			}
			if result.BodyShapeMatch != tt.wantBodyMatch {
				t.Fatalf("body shape match = %v, want %v; diff = %#v", result.BodyShapeMatch, tt.wantBodyMatch, result.BodyShapeDiff)
			}
		})
	}
}

func TestReplayOneTimeoutReturnsErrorCategory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = 10 * time.Millisecond
	flow := serverFlow(server.URL, "GET", "/slow", http.StatusOK, nil, []byte(`{"ok":true}`), nil)

	result := ReplayOne(context.Background(), client, flow, Options{}, nil)
	if result.Category != "error" || result.Error == "" {
		t.Fatalf("result = %#v, want timeout error", result)
	}
}

func TestGoldenDryRunFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "golden", "phase5", "replay", "flows.jsonl")
	expectedPath := filepath.Join("..", "..", "testdata", "golden", "phase5", "replay", "expected-dry-run.json")
	summary, err := Run(context.Background(), Options{BundleOrDomain: path, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	summary.Domain = ""
	var expected Summary
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(summary, expected) {
		t.Fatalf("summary = %#v, want %#v", summary, expected)
	}
}

func serverFlow(baseURL, method, path string, status int, requestBody, responseBody []byte, requestHeaders map[string]string) model.CapturedFlow {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		panic(err)
	}
	if requestHeaders == nil {
		requestHeaders = map[string]string{}
	}
	return model.CapturedFlow{
		Method:          method,
		Host:            parsed.Hostname(),
		Path:            path,
		URL:             strings.TrimRight(baseURL, "/") + path,
		RequestHeaders:  requestHeaders,
		RequestBody:     requestBody,
		ResponseStatus:  status,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    responseBody,
		BodyEncoding:    "base64",
		Timestamp:       1,
	}
}

func writeFlows(t *testing.T, path string, flows []model.CapturedFlow) {
	t.Helper()
	var lines []string
	for _, flow := range flows {
		line, err := flow.ToJSONL()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDeduplicateReportsMerges(t *testing.T) {
	flows := []model.CapturedFlow{
		{Method: "GET", Path: "/creditcards/cc_9BMqukMwYVs6SY1psJlh0f", Timestamp: 1},
		{Method: "GET", Path: "/creditcards/cc_7w7CLKmd9I77HX2fjHfGPB", Timestamp: 2},
		{Method: "GET", Path: "/users/search", Timestamp: 3},
		{Method: "GET", Path: "/users/notifications", Timestamp: 4},
	}
	deduped, merges := deduplicate(flows)
	if len(deduped) != 3 {
		t.Fatalf("deduped = %d, want 3", len(deduped))
	}
	if len(merges) != 1 {
		t.Fatalf("merges = %#v, want exactly one (the two credit-card ids)", merges)
	}
	m := merges[0]
	wantPaths := []string{
		"/creditcards/cc_7w7CLKmd9I77HX2fjHfGPB",
		"/creditcards/cc_9BMqukMwYVs6SY1psJlh0f",
	}
	if m.Method != "GET" || !reflect.DeepEqual(m.Paths, wantPaths) {
		t.Fatalf("merge = %#v, want GET with the two collapsed cc_ paths %#v", m, wantPaths)
	}
}

// A single route captured multiple times must NOT register as a merge: the
// merge log exists to surface distinct paths collapsing, not repeat captures.
func TestDeduplicateSamePathNotMerged(t *testing.T) {
	flows := []model.CapturedFlow{
		{Method: "GET", Path: "/users/search", Timestamp: 1},
		{Method: "GET", Path: "/users/search", Timestamp: 2},
	}
	deduped, merges := deduplicate(flows)
	if len(deduped) != 1 {
		t.Fatalf("deduped = %d, want 1", len(deduped))
	}
	if len(merges) != 0 {
		t.Fatalf("merges = %#v, want none (same path captured twice is not a merge)", merges)
	}
}

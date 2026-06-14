package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

func chromeTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cdp-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestCDPCapturesLargeJSONResponseBody(t *testing.T) {
	skipUnlessChrome(t)
	setTestHome(t, chromeTempDir(t))
	largePayload := strings.Repeat("a", 2*1024*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("content-type", "text/html")
			w.Write([]byte(`<script>
				fetch("/api/large").then(r => r.json()).then(() => { document.title = "done"; });
			</script>`))
		case "/api/large":
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"data":"` + largePayload + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := Capture(ctx, Config{
		Domain:      "127.0.0.1",
		URL:         server.URL,
		Mode:        "cdp-launch",
		Port:        freePort(t),
		UserDataDir: chromeTempDir(t),
		Headless:    true,
		Timeout:     30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	flow := findFlowByPath(flows, "/api/large")
	if flow == nil {
		t.Fatalf("missing /api/large flow: %#v", flows)
	}
	if len(flow.ResponseBody) < len(largePayload) {
		t.Fatalf("large response body was not captured: got %d want at least %d", len(flow.ResponseBody), len(largePayload))
	}
	if !hasTagPrefix(flow.Tags, "response_body_bytes:") || !hasTagPrefix(flow.Tags, "response_encoded_bytes:") {
		t.Fatalf("missing body size tags: %#v", flow.Tags)
	}
}

func TestCDPCapturesWebSocketFrames(t *testing.T) {
	skipUnlessChrome(t)
	setTestHome(t, chromeTempDir(t))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("content-type", "text/html")
			w.Write([]byte(`<script>
				const ws = new WebSocket("ws://" + location.host + "/api/ws");
				ws.onopen = () => ws.send("client-ready");
				ws.onmessage = event => { document.title = "ws-done"; ws.close(); };
			</script>`))
		case "/api/ws":
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err != nil {
				return
			}
			defer conn.Close()
			msg, op, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			wsutil.WriteServerMessage(conn, op, []byte(`{"echo":`+quoteJSON(msg)+`}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := Capture(ctx, Config{
		Domain:      "127.0.0.1",
		URL:         server.URL,
		Mode:        "cdp-launch",
		Port:        freePort(t),
		UserDataDir: chromeTempDir(t),
		Headless:    true,
		Timeout:     30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	flows, err := adapter.LoadJSONL(result.FlowsPath)
	if err != nil {
		t.Fatal(err)
	}
	flow := findFlowByPath(flows, "/api/ws")
	if flow == nil {
		t.Fatalf("missing /api/ws flow: %#v", flows)
	}
	if !hasTag(flow.Tags, "websocket") || !hasTagPrefix(flow.Tags, "websocket_sent_frames:") || !hasTagPrefix(flow.Tags, "websocket_received_frames:") {
		t.Fatalf("missing websocket tags: %#v", flow.Tags)
	}
	if !bytes.Contains(flow.ResponseBody, []byte("client-ready")) || !bytes.Contains(flow.ResponseBody, []byte("echo")) {
		t.Fatalf("websocket payload summary missing expected frames: %s", flow.ResponseBody)
	}
}

func findFlowByPath(flows []model.CapturedFlow, path string) *model.CapturedFlow {
	for i := range flows {
		if flows[i].Path == path {
			return &flows[i]
		}
	}
	return nil
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func hasTagPrefix(tags []string, prefix string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, prefix) {
			return true
		}
	}
	return false
}

func quoteJSON(value []byte) string {
	data, _ := json.Marshal(string(value))
	return string(data)
}

func skipUnlessChrome(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("CDP tests skipped on Windows: Chrome debug websocket not reliable on CI runners")
	}
	path := FindChrome()
	if runtime.GOOS == "darwin" && strings.HasPrefix(path, "/") {
		if _, err := os.Stat(path); err == nil {
			return
		}
		t.Skipf("Chrome not found at %s", path)
	}
	if _, err := exec.LookPath(path); err != nil {
		t.Skipf("Chrome not found: %v", err)
	}
}

func TestCaptureEmptyModeDefaultsToProxyWithLaunch(t *testing.T) {
	got := applyDefaults(Config{Domain: "example.com"})
	if got.Mode != "proxy" {
		t.Errorf("Mode = %q, want proxy", got.Mode)
	}
	if !got.LaunchBrowser {
		t.Error("implicit default must launch a browser (old cdp-launch contract)")
	}
	if got.URL != "https://example.com" {
		t.Errorf("URL = %q, want https://example.com", got.URL)
	}
}

func TestCaptureExplicitProxyNoBrowserPreserved(t *testing.T) {
	got := applyDefaults(Config{Domain: "example.com", Mode: "proxy", LaunchBrowser: false})
	if got.LaunchBrowser {
		t.Error("explicit Mode:proxy must NOT be forced to launch a browser")
	}
}

func TestCaptureExplicitCDPLaunchPreserved(t *testing.T) {
	got := applyDefaults(Config{Domain: "example.com", Mode: "cdp-launch"})
	if got.Mode != "cdp-launch" {
		t.Errorf("Mode = %q, want cdp-launch (no proxy regression)", got.Mode)
	}
	if got.LaunchBrowser {
		t.Error("explicit cdp-launch must NOT be flipped to a proxy-launched browser")
	}
}

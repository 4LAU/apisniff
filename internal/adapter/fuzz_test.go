package adapter

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

// Untrusted-input contract for importers: never panic, and any flow returned
// has a usable method and an absolute URL.

func FuzzLoadHAR(f *testing.F) {
	f.Add([]byte(`{"log":{"entries":[{"startedDateTime":"2026-01-02T03:04:05Z","request":{"method":"GET","url":"https://example.com/api?x=1","headers":[{"name":"Accept","value":"application/json"}]},"response":{"status":200,"headers":[{"name":"Content-Type","value":"application/json"}],"content":{"text":"eyJvayI6dHJ1ZX0=","encoding":"base64"}}}]}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"url":"relative/path"},"response":{"content":{"text":"!!!not base64!!!","encoding":"base64"}}}]}}`))
	f.Add([]byte(`{"log":{"entries":[{}]}}`))
	f.Add([]byte(`{"log"`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "in.har")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		flows, err := LoadHAR(path)
		if err != nil {
			return
		}
		assertImportedFlowsUsable(t, flows)
	})
}

func FuzzLoadBurp(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><items><item><url>https://example.com/api</url><method>GET</method><status>200</status><request base64="true">R0VUIC9hcGkgSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg==</request><response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0Ke30=</response></item></items>`))
	f.Add([]byte(`<items><item><url>not a url</url><request base64="true">!!!</request></item></items>`))
	f.Add([]byte(`<items><item></item>`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "in.xml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		flows, err := LoadBurp(path)
		if err != nil {
			return
		}
		assertImportedFlowsUsable(t, flows)
	})
}

func assertImportedFlowsUsable(t *testing.T, flows []model.CapturedFlow) {
	t.Helper()
	for _, flow := range flows {
		if flow.Method == "" {
			t.Fatalf("imported flow without method: %#v", flow)
		}
		parsed, err := url.Parse(flow.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			t.Fatalf("imported flow without absolute URL: %q (err=%v)", flow.URL, err)
		}
	}
}

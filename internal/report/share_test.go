package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func TestBuildInventoryRedactsCookies(t *testing.T) {
	flows := []model.CapturedFlow{{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/users/123",
		URL:             "https://example.com/api/users/123",
		RequestHeaders:  map[string]string{"Cookie": "sid=secret"},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"Set-Cookie": "session=abc; Path=/; Secure"},
		Tags:            []string{"category:business_api"},
	}}

	inventory := BuildInventory(flows, "example.com")
	if inventory.Cookies[0].Value != "[redacted]" || inventory.Cookies[1].Value != "[redacted]" {
		t.Fatalf("cookies were not redacted: %#v", inventory.Cookies)
	}
	if inventory.Categories["business_api"] != 1 {
		t.Fatalf("categories = %#v", inventory.Categories)
	}
	if inventory.TopEndpoints[0].Path != "/api/users/{userId}" {
		t.Fatalf("endpoint = %#v", inventory.TopEndpoints[0])
	}
}

func TestShareWritesOnlyDerivedArtifacts(t *testing.T) {
	bundle := t.TempDir()
	output := filepath.Join(t.TempDir(), "share")
	flow := model.CapturedFlow{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/users",
		URL:             "https://example.com/api/users",
		RequestHeaders:  map[string]string{"Cookie": "sid=secret"},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    []byte(`{"password":"secret","name":"Ada"}`),
		BodyEncoding:    "base64",
		Tags:            []string{"category:business_api"},
	}
	line, err := flow.ToJSONL()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "flows.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "session.json"), []byte(`{"domain":"example.com","total_flows":1,"kept_flows":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Share(ShareOptions{BundleOrDomain: bundle, OutputDir: output})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Files, ",") != "spec.yaml,inventory.json,report.md,session.json" {
		t.Fatalf("files = %#v", result.Files)
	}
	if _, err := os.Stat(filepath.Join(output, "flows.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("raw flows were exported")
	}
	data, err := os.ReadFile(filepath.Join(output, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Cookies) == 0 || inventory.Cookies[0].Value != "[redacted]" {
		t.Fatalf("inventory cookies = %#v", inventory.Cookies)
	}
	if strings.Contains(string(data), "sid=secret") {
		t.Fatalf("inventory leaked cookie value: %s", data)
	}
}

func TestShareOutputContainsNoRawTrafficFields(t *testing.T) {
	bundle := t.TempDir()
	output := filepath.Join(t.TempDir(), "share")
	flow := model.CapturedFlow{
		Method:          "POST",
		Host:            "example.com",
		Path:            "/api/login",
		URL:             "https://example.com/api/login",
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     []byte(`{"email":"user@example.com","password":"hunter2"}`),
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    []byte(`{"token":"eyJhbGciOiJSUzI1NiJ9.payload"}`),
		BodyEncoding:    "base64",
		Tags:            []string{"category:business_api"},
	}
	writeBundleForShareTest(t, bundle, []model.CapturedFlow{flow})

	if _, err := Share(ShareOptions{BundleOrDomain: bundle, OutputDir: output}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inventory.json", "session.json"} {
		data, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, rawField := range []string{"request_body", "response_body"} {
			if strings.Contains(text, rawField) {
				t.Fatalf("%s leaked raw traffic field %q:\n%s", name, rawField, text)
			}
		}
	}
}

func TestShareSkipsSpecWhenNoValidAPIFlows(t *testing.T) {
	bundle := t.TempDir()
	output := filepath.Join(t.TempDir(), "share")
	flow := model.CapturedFlow{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/",
		URL:             "https://example.com/",
		RequestHeaders:  map[string]string{},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "text/html"},
		ResponseBody:    []byte("<html>not api</html>"),
		BodyEncoding:    "base64",
	}
	writeBundleForShareTest(t, bundle, []model.CapturedFlow{flow})

	result, err := Share(ShareOptions{BundleOrDomain: bundle, OutputDir: output})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Files, ",") != "inventory.json,report.md,session.json" {
		t.Fatalf("files = %#v", result.Files)
	}
	if _, err := os.Stat(filepath.Join(output, "spec.yaml")); !os.IsNotExist(err) {
		t.Fatalf("spec.yaml was written for a bundle with no valid API flows")
	}
	for _, name := range []string{"inventory.json", "report.md", "session.json"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
	}
}

func TestShareOutputContainsNoCredentialValues(t *testing.T) {
	bundle := t.TempDir()
	output := filepath.Join(t.TempDir(), "share")
	flow := model.CapturedFlow{
		Method: "POST",
		Host:   "example.com",
		Path:   "/api/users?api_key=secret_key_999",
		URL:    "https://example.com/api/users?api_key=secret_key_999",
		RequestHeaders: map[string]string{
			"authorization": "Bearer sk_live_secret",
			"cookie":        "session=abc123",
			"content-type":  "application/json",
		},
		RequestBody:     []byte(`{"password":"hunter2","email":"alice@example.com"}`),
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json", "set-cookie": "session_id_abc123=value; Path=/"},
		ResponseBody:    []byte(`{"token":"eyJhbGciOiJSUzI1NiJ9.payload","ssn":"123-45-6789"}`),
		BodyEncoding:    "base64",
		Tags:            []string{"category:business_api", "token=tag_secret_999"},
	}
	writeBundleForShareTest(t, bundle, []model.CapturedFlow{flow})

	if _, err := Share(ShareOptions{BundleOrDomain: bundle, OutputDir: output}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(output, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, secret := range []string{"sk_live_secret", "session=abc123", "secret_key_999", "hunter2", "alice@example.com", "eyJhbGciOiJSUzI1NiJ9", "123-45-6789", "tag_secret_999"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s leaked secret %q:\n%s", entry.Name(), secret, text)
			}
		}
	}
}

func TestShareRegeneratesReportInsteadOfCopyingSource(t *testing.T) {
	bundle := t.TempDir()
	output := filepath.Join(t.TempDir(), "share")
	writeBundleForShareTest(t, bundle, []model.CapturedFlow{{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/users",
		URL:             "https://example.com/api/users",
		RequestHeaders:  map[string]string{},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    []byte(`{"ok":true}`),
		BodyEncoding:    "base64",
		Tags:            []string{"category:business_api"},
	}})
	if err := os.WriteFile(filepath.Join(bundle, "report.md"), []byte("# stale\nleaked_cookie_value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Share(ShareOptions{BundleOrDomain: bundle, OutputDir: output}); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(filepath.Join(output, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report), "leaked_cookie_value") {
		t.Fatalf("stale source report was copied:\n%s", report)
	}
	if !strings.Contains(string(report), "example.com") {
		t.Fatalf("regenerated report missing domain:\n%s", report)
	}
}

func writeBundleForShareTest(t *testing.T, bundle string, flows []model.CapturedFlow) {
	t.Helper()
	var lines []string
	for _, flow := range flows {
		line, err := flow.ToJSONL()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := os.WriteFile(filepath.Join(bundle, "flows.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	session := fmt.Sprintf(`{"domain":"example.com","total_flows":%d,"kept_flows":%d}`, len(flows), len(flows))
	if err := os.WriteFile(filepath.Join(bundle, "session.json"), []byte(session), 0o600); err != nil {
		t.Fatal(err)
	}
}

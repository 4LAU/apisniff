package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4LAU/apisniff-go/internal/model"
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
	if inventory.TopEndpoints[0].Path != "/api/users/{id}" {
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

package spec

import (
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func surfaceFlow(overrides func(*model.CapturedFlow)) model.CapturedFlow {
	flow := model.CapturedFlow{
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/v1/users",
		URL:             "https://example.com/api/v1/users",
		RequestHeaders:  map[string]string{},
		ResponseStatus:  200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    []byte(`{"data":[]}`),
		BodyEncoding:    "base64",
		Tags:            []string{"source:raw"},
	}
	if overrides != nil {
		overrides(&flow)
	}
	return flow
}

func TestBuildSurfaceInventoryClassifiesAllFlows(t *testing.T) {
	flows := []model.CapturedFlow{
		surfaceFlow(nil),
		surfaceFlow(func(f *model.CapturedFlow) {
			f.Host = "cdn.unrelated.test"
			f.URL = "https://cdn.unrelated.test/widget.js"
			f.Path = "/widget.js"
			f.ResponseHeaders = map[string]string{"content-type": "application/javascript"}
			f.ResponseBody = []byte("console.log('widget')")
		}),
	}

	inventory := BuildSurfaceInventory(flows, "example.com")
	if inventory.SchemaVersion != 1 || inventory.TotalFlows != 2 || inventory.KeptFlows != 1 || inventory.DroppedFlows != 1 {
		t.Fatalf("inventory counts = %+v", inventory)
	}
	if inventory.Categories[string(model.BusinessAPI)] != 1 || inventory.Categories[string(model.ThirdPartyAPI)] != 1 {
		t.Fatalf("categories = %#v", inventory.Categories)
	}
	if len(inventory.Flows) != 2 || inventory.Flows[0].Category != model.BusinessAPI || inventory.Flows[1].Category != model.ThirdPartyAPI {
		t.Fatalf("flows = %#v", inventory.Flows)
	}
}

func TestApplyInclusionFiltersAddsCategoryTagsToKeptFlows(t *testing.T) {
	flows := []model.CapturedFlow{surfaceFlow(func(f *model.CapturedFlow) {
		f.Tags = []string{"source:raw", "category:stale"}
	})}

	filtered, inventory, err := ApplyInclusionFilters(flows, "example.com", InclusionOptions{})
	if err != nil {
		t.Fatalf("ApplyInclusionFilters error: %v", err)
	}
	if inventory.KeptFlows != 1 || len(filtered) != 1 {
		t.Fatalf("inventory=%+v filtered=%+v", inventory, filtered)
	}
	if !hasSpecTag(filtered[0].Tags, "source:raw") || !hasSpecTag(filtered[0].Tags, "category:business_api") || hasSpecTag(filtered[0].Tags, "category:stale") {
		t.Fatalf("tags = %#v", filtered[0].Tags)
	}
	if len(FilterAPIFlows(filtered)) != 1 {
		t.Fatalf("categorized kept flow was not included by FilterAPIFlows")
	}
}

func TestApplyInclusionFiltersIncludesThirdPartyDrops(t *testing.T) {
	flows := []model.CapturedFlow{
		surfaceFlow(nil),
		surfaceFlow(func(f *model.CapturedFlow) {
			f.Host = "api.partner.test"
			f.URL = "https://api.partner.test/v1/accounts"
			f.Path = "/v1/accounts"
			f.Method = "DELETE"
			f.ResponseHeaders = map[string]string{"content-type": "text/plain"}
			f.ResponseBody = []byte("ok")
		}),
	}

	filtered, _, err := ApplyInclusionFilters(flows, "example.com", InclusionOptions{IncludeThirdParty: true})
	if err != nil {
		t.Fatalf("ApplyInclusionFilters error: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("filtered = %+v", filtered)
	}
	if !hasSpecTag(filtered[1].Tags, "category:third_party_api") {
		t.Fatalf("third-party tags = %#v", filtered[1].Tags)
	}
	if !hasSpecTag(filtered[1].Tags, includedForSpecTag) {
		t.Fatalf("third-party tags missing force include marker = %#v", filtered[1].Tags)
	}
	if len(FilterAPIFlows(filtered)) != 2 {
		t.Fatalf("included third-party flow was re-dropped by FilterAPIFlows: %+v", filtered)
	}
}

func TestApplyInclusionFiltersIncludesCategories(t *testing.T) {
	flows := []model.CapturedFlow{
		surfaceFlow(func(f *model.CapturedFlow) {
			f.Path = "/rum.gif"
			f.URL = "https://example.com/rum.gif"
		}),
	}

	filtered, _, err := ApplyInclusionFilters(flows, "example.com", InclusionOptions{IncludeCategories: []string{"CATEGORY:Telemetry"}})
	if err != nil {
		t.Fatalf("ApplyInclusionFilters error: %v", err)
	}
	if len(filtered) != 1 || !hasSpecTag(filtered[0].Tags, "category:telemetry") {
		t.Fatalf("filtered = %+v", filtered)
	}
}

func TestApplyInclusionFiltersIncludesHostsCaseInsensitiveAndPortTolerant(t *testing.T) {
	flows := []model.CapturedFlow{
		surfaceFlow(func(f *model.CapturedFlow) {
			f.Host = "API.Partner.test:8443"
			f.URL = "https://API.Partner.test:8443/v1/accounts"
			f.Path = "/v1/accounts"
		}),
	}

	filtered, _, err := ApplyInclusionFilters(flows, "example.com", InclusionOptions{IncludeHosts: []string{"api.partner.test"}})
	if err != nil {
		t.Fatalf("ApplyInclusionFilters error: %v", err)
	}
	if len(filtered) != 1 || !hasSpecTag(filtered[0].Tags, "category:third_party_api") {
		t.Fatalf("filtered = %+v", filtered)
	}
}

func hasSpecTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

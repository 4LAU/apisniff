package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/adapter"
	"github.com/4LAU/apisniff/internal/model"
)

func TestPrepareFilteredFlowInjectsTagsAndStripsBodies(t *testing.T) {
	flow := testFilteredFlow()
	flow.Tags = []string{"existing", "category:" + string(model.Telemetry)}

	filtered := prepareFilteredFlow(flow, model.ClassifyResult{
		Category: model.Telemetry,
		Reason:   "noise_domain",
	})

	assertHasTag(t, filtered.Tags, "existing")
	assertHasTag(t, filtered.Tags, "filter_reason:noise_domain")
	assertHasTag(t, filtered.Tags, "category:telemetry")
	assertHasTag(t, filtered.Tags, "body_stripped")
	assertTagCount(t, filtered.Tags, "category:telemetry", 1)
	if len(filtered.RequestBody) != 0 || len(filtered.ResponseBody) != 0 {
		t.Fatalf("filtered bodies = request %q response %q, want stripped", filtered.RequestBody, filtered.ResponseBody)
	}
}

func TestPrepareFilteredFlowFallsBackToCategoryWhenReasonEmpty(t *testing.T) {
	filtered := prepareFilteredFlow(testFilteredFlow(), model.ClassifyResult{
		Category: model.Static,
	})

	assertHasTag(t, filtered.Tags, "filter_reason:static")
	assertHasTag(t, filtered.Tags, "category:static")
}

func TestPrepareFilteredFlowStripsBodiesForNoiseReasons(t *testing.T) {
	tests := []struct {
		name     string
		category model.SurfaceCategory
		reason   string
	}{
		{name: "static asset", category: model.Static, reason: "static_asset"},
		{name: "CORS preflight", category: model.Options, reason: "CORS preflight"},
		{name: "noise domain", category: model.Telemetry, reason: "noise_domain"},
		{name: "path telemetry", category: model.Telemetry, reason: "path_telemetry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := prepareFilteredFlow(testFilteredFlow(), model.ClassifyResult{
				Category: tt.category,
				Reason:   tt.reason,
			})

			assertHasTag(t, filtered.Tags, "body_stripped")
			if len(filtered.RequestBody) != 0 || len(filtered.ResponseBody) != 0 {
				t.Fatalf("filtered bodies = request %q response %q, want stripped", filtered.RequestBody, filtered.ResponseBody)
			}
		})
	}
}

func TestPrepareFilteredFlowPreservesBodiesForNonNoiseReasons(t *testing.T) {
	tests := []struct {
		name     string
		category model.SurfaceCategory
		reason   string
	}{
		{name: "third party", category: model.ThirdPartyAPI, reason: "third_party"},
		{name: "same site noise", category: model.Telemetry, reason: "same_site_noise"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := testFilteredFlow()
			filtered := prepareFilteredFlow(flow, model.ClassifyResult{
				Category: tt.category,
				Reason:   tt.reason,
			})

			assertNoTag(t, filtered.Tags, "body_stripped")
			if !reflect.DeepEqual(filtered.RequestBody, flow.RequestBody) {
				t.Fatalf("request body = %q, want %q", filtered.RequestBody, flow.RequestBody)
			}
			if !reflect.DeepEqual(filtered.ResponseBody, flow.ResponseBody) {
				t.Fatalf("response body = %q, want %q", filtered.ResponseBody, flow.ResponseBody)
			}
		})
	}
}

func TestPrepareFilteredFlowStripsBodiesForSensorDataSignal(t *testing.T) {
	filtered := prepareFilteredFlow(testFilteredFlow(), model.ClassifyResult{
		Category: model.Antibot,
		Reason:   "same_site_noise",
		Signals:  []string{"same_site_noise", "sensor_data"},
	})

	assertHasTag(t, filtered.Tags, "filter_reason:same_site_noise")
	assertHasTag(t, filtered.Tags, "category:antibot")
	assertHasTag(t, filtered.Tags, "body_stripped")
	if len(filtered.RequestBody) != 0 || len(filtered.ResponseBody) != 0 {
		t.Fatalf("filtered bodies = request %q response %q, want stripped", filtered.RequestBody, filtered.ResponseBody)
	}
}

func TestPrepareFilteredFlowStrippedBodiesSerializeAsNull(t *testing.T) {
	filtered := prepareFilteredFlow(testFilteredFlow(), model.ClassifyResult{
		Category: model.Telemetry,
		Reason:   "path_telemetry",
	})

	line, err := filtered.ToJSONL()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatal(err)
	}
	if value, ok := raw["request_body"]; !ok || value != nil {
		t.Fatalf("request_body = %#v, want null", value)
	}
	if value, ok := raw["response_body"]; !ok || value != nil {
		t.Fatalf("response_body = %#v, want null", value)
	}
}

func TestFilteredFlowsPersistToFilteredJSONL(t *testing.T) {
	bundleDir := t.TempDir()
	path := FilteredPath(bundleDir)
	if path != filepath.Join(bundleDir, "filtered.jsonl") {
		t.Fatalf("FilteredPath() = %q, want filtered.jsonl in bundle dir", path)
	}

	writer, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	filtered := prepareFilteredFlow(testFilteredFlow(), model.ClassifyResult{
		Category: model.Telemetry,
		Reason:   "noise_domain",
	})
	if err := writer.Write(filtered); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	flows, err := adapter.LoadJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	assertHasTag(t, flows[0].Tags, "filter_reason:noise_domain")
	assertHasTag(t, flows[0].Tags, "category:telemetry")
	assertHasTag(t, flows[0].Tags, "body_stripped")
	if len(flows[0].RequestBody) != 0 || len(flows[0].ResponseBody) != 0 {
		t.Fatalf("persisted bodies = request %q response %q, want stripped", flows[0].RequestBody, flows[0].ResponseBody)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 1 {
		t.Fatalf("filtered.jsonl lines = %d, want 1", len(lines))
	}
}

func testFilteredFlow() model.CapturedFlow {
	return model.CapturedFlow{
		Method:          "POST",
		Host:            "example.com",
		Path:            "/collect",
		URL:             "https://example.com/collect",
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     []byte(`{"event":"pageview"}`),
		ResponseStatus:  204,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    []byte(`{"ok":true}`),
		BodyEncoding:    "base64",
		Tags:            []string{"captured"},
		Timestamp:       1710000000,
	}
}

func assertHasTag(t *testing.T, tags []string, want string) {
	t.Helper()
	for _, tag := range tags {
		if tag == want {
			return
		}
	}
	t.Fatalf("tags = %#v, missing %q", tags, want)
}

func assertNoTag(t *testing.T, tags []string, unwanted string) {
	t.Helper()
	for _, tag := range tags {
		if tag == unwanted {
			t.Fatalf("tags = %#v, did not want %q", tags, unwanted)
		}
	}
}

func assertTagCount(t *testing.T, tags []string, want string, count int) {
	t.Helper()
	got := 0
	for _, tag := range tags {
		if tag == want {
			got++
		}
	}
	if got != count {
		t.Fatalf("tag %q count = %d, want %d in %#v", want, got, count, tags)
	}
}

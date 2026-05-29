package capture

import (
	"path/filepath"

	"github.com/4LAU/apisniff/internal/model"
)

var filteredBodyStripReasons = map[string]struct{}{
	"static_asset":   {},
	"CORS preflight": {},
	"noise_domain":   {},
	"path_telemetry": {},
}

func FilteredPath(bundleDir string) string {
	return filepath.Join(bundleDir, "filtered.jsonl")
}

func prepareFilteredFlow(flow model.CapturedFlow, result model.ClassifyResult) model.CapturedFlow {
	reason := result.Reason
	if reason == "" {
		reason = string(result.Category)
	}

	flow.Tags = appendTag(flow.Tags, "filter_reason:"+reason)
	flow.Tags = appendTag(flow.Tags, "category:"+string(result.Category))

	if shouldStripFilteredBodies(result) {
		flow.RequestBody = nil
		flow.ResponseBody = nil
		flow.Tags = appendTag(flow.Tags, "body_stripped")
	}

	return flow
}

func shouldStripFilteredBodies(result model.ClassifyResult) bool {
	if _, ok := filteredBodyStripReasons[result.Reason]; ok {
		return true
	}
	for _, signal := range result.Signals {
		if signal == "sensor_data" {
			return true
		}
	}
	return false
}

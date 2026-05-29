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

type lazyFilteredWriter struct {
	path     string
	writer   *JSONLWriter
	disabled bool
}

func newLazyFilteredWriter(bundleDir string) *lazyFilteredWriter {
	return &lazyFilteredWriter{path: FilteredPath(bundleDir)}
}

func (lw *lazyFilteredWriter) Write(flow model.CapturedFlow, result model.ClassifyResult) {
	if lw.disabled {
		return
	}
	if lw.writer == nil {
		w, err := NewJSONLWriter(lw.path)
		if err != nil {
			lw.disabled = true
			return
		}
		lw.writer = w
	}
	_ = lw.writer.Write(prepareFilteredFlow(flow, result))
}

func (lw *lazyFilteredWriter) Close() string {
	if lw.writer == nil {
		return ""
	}
	w := lw.writer
	lw.writer = nil
	if w.Close() != nil || w.Count() == 0 {
		return ""
	}
	return lw.path
}

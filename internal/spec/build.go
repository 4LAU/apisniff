package spec

import (
	"github.com/4LAU/apisniff/internal/auth"
	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/model"
)

// PipelineResult is the shared input set for spec generation.
type PipelineResult struct {
	// Selected is the auth-evidence set: every flow that survived inclusion
	// selection, with kept flows category-tagged. Without inclusion filters
	// this is all input flows.
	Selected []model.CapturedFlow
	// APIFlows is the subset of Selected that can contribute operations.
	APIFlows []model.CapturedFlow
	// Auth is detected from Selected, not APIFlows: session cookies and auth
	// headers are usually observed on document flows that never become
	// operations.
	Auth    []auth.Pattern
	Surface SurfaceInventory
}

// BuildPipeline is the single entrypoint 'apisniff spec' and 'apisniff share'
// use, so operation inputs, auth evidence, and surface categorization cannot
// drift between commands.
func BuildPipeline(flows []model.CapturedFlow, domain string, inclusions InclusionOptions) (PipelineResult, error) {
	var result PipelineResult
	if inclusions.Enabled() {
		selected, surface, err := ApplyInclusionFilters(flows, domain, inclusions)
		if err != nil {
			return PipelineResult{}, err
		}
		result.Selected = selected
		result.Surface = surface
	} else {
		classifier, err := classify.New(domain)
		if err != nil {
			return PipelineResult{}, err
		}
		classified := classifyFlows(flows, classifier)
		result.Surface = buildSurfaceInventory(classified, domain)
		selected := make([]model.CapturedFlow, 0, len(flows))
		for _, item := range classified {
			if item.result.Action == "keep" && item.kept != nil {
				selected = append(selected, *item.kept)
				continue
			}
			selected = append(selected, item.flow)
		}
		result.Selected = selected
	}
	result.Auth = auth.Detect(result.Selected)
	result.APIFlows = FilterAPIFlows(result.Selected)
	return result, nil
}

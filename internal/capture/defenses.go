package capture

import (
	"sort"
	"strings"

	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/vendor"
)

// defenseSignals maps confidence-stripped (type:rest) signal keys that imply an
// active mitigation — a challenge header, a bot-management cookie, a
// CAPTCHA/challenge body marker, or a WAF action. defenseSignalAllowed returns
// true only for these.
//
// infraSignals maps the known presence/infra/load-balancer keys that prove a
// vendor is merely fronting the target, not mitigating it. The predicate does
// NOT consult infraSignals; it exists so the completeness test can assert every
// emittable label is classified (defenseSignals ∪ infraSignals), forcing a human
// to classify any new signature added to vendors.json instead of silently
// rendering it as a defense.
//
// Keys are taken verbatim from the detector's label() output: header/cookie keys
// are lowercased; body: values and *_regex: patterns preserve original case.
var (
	defenseSignals = map[string]bool{
		// cloudflare
		"header:cf-mitigated":            true,
		"body:challenges.cloudflare.com": true,
		"cookie:cf_clearance":            true,
		"cookie:__cf_bm":                 true,
		// akamai
		"cookie:_abck":   true,
		"body:bmak.":     true,
		"cookie:ak_bmsc": true,
		"cookie:bm_sz":   true,
		"cookie:sbsd":    true,
		// datadome
		"cookie:datadome":       true,
		"header:x-datadome-cid": true,
		"header:x-dd-b":         true,
		// perimeterx
		"body:window._pxAppId":      true,
		"body:pxInit":               true,
		"cookie:_px2":               true,
		"cookie:_px3":               true,
		"header:x-px-authorization": true,
		"cookie:_pxhd":              true,
		"cookie:_pxvid":             true,
		// imperva
		"body:incapsula": true,
		"body:imperva":   true,
		"cookie:reese84": true,
		"header:x-cdn":   true,
		"header:x-iinfo": true,
		"cookie:utmvc":   true,
		// kasada
		"header:x-kasada":           true,
		"header:x-kasada-challenge": true,
		"body:__kasada":             true,
		"body:kasada.js":            true,
		// shape_security
		"header_regex:^x-[a-z0-9]{8}-[abcdfz]$": true,
		"body:shapesecurity":                    true,
		// aws_waf
		"header:x-amzn-waf-action": true,
		"cookie:aws-waf-token":     true,
		"body:aws-waf":             true,
		"body:awswaf":              true,
		// recaptcha
		"body:recaptcha/api":         true,
		"body:gstatic.com/recaptcha": true,
		"body:g-recaptcha":           true,
		"body:grecaptcha":            true,
		// hcaptcha
		"body:hcaptcha.com": true,
		"body:h-captcha":    true,
		// cloudflare_turnstile
		"body:challenges.cloudflare.com/turnstile": true,
		"body:cf-turnstile":                        true,
		// vercel
		"header:x-vercel-mitigated": true,
		// reblaze
		"cookie:rbzid":        true,
		"cookie:rbzsessionid": true,
		// cheq
		"body:CheqSdk":      true,
		"body:cheqzone.com": true,
		// sucuri
		"body:sucuri": true,
		// arkose_labs
		"body:arkoselabs.com": true,
		"body:funcaptcha":     true,
		// geetest
		"body:geetest.com": true,
		// anubis
		`body:<script id="anubis_challenge">`: true,
		"body:/.within.website/x/cmd/anubis/": true,
		// threatmetrix
		"body:ThreatMetrix": true,
		// meetrics
		"body:meetricsGlobal": true,
		// ocule
		"body:proxy.ocule.co.uk/script.js": true,
		// amazon_cloudfront CAPTCHA marker (DEFENSE, even though x-cache is INFRA)
		"body:csm-captcha-instrumentation": true,
		// linkedin block status
		"status:999": true,
		// reddit block page
		"body:blocked by network security": true,
	}

	infraSignals = map[string]bool{
		"header:cf-ray":                 true, // cloudflare presence
		"header:akamai-grn":             true, // akamai cache
		"header:akamai-cache-status":    true, // akamai cache
		"header:x-amzn-requestid":       true, // aws api gateway presence
		"header:x-cache":                true, // amazon_cloudfront CDN error, not mitigation
		"cookie_prefix:bigipserver":     true, // f5 load-balancer persistence
		"cookie_regex:^TS[a-zA-Z0-9]+$": true, // f5 load-balancer persistence
	}
)

// detectDefenses runs the vendor detector over a target-owned flow's response and
// returns the defense-implying matches plus whether the flow was in defense scope
// (so the caller gates the unattributed-antibot counter on the same decision).
func detectDefenses(det *vendor.Detector, targetRD string, flow model.CapturedFlow, c model.ClassifyResult) (matches []model.VendorMatch, scoped bool) {
	if det == nil || !inScopeForDefenses(targetRD, flow, c) {
		return nil, false
	}
	return filterDefenseMatches(det.Match(flow.ResponseHeaders, flow.ResponseBody, flow.ResponseStatus)), true
}

// inScopeForDefenses keeps detection on TARGET-owned flows only. same_site and
// third_party are OUT: a referer/CSP-linked dependency carries its OWN vendor's
// cookies, and attributing them to the target is the exact misattribution this
// design avoids. Empty HostRole (OPTIONS preflight / path_telemetry early
// returns, both before hostRole is set) falls back to matching the registered
// domain against the target, since a target-host OPTIONS/telemetry response can
// still carry a real defense cookie.
func inScopeForDefenses(targetRD string, flow model.CapturedFlow, c model.ClassifyResult) bool {
	switch c.HostRole {
	case "target":
		return true
	case "same_site", "third_party":
		return false
	default: // "" early-return flows: fall back to host (target registered domain only)
		return classify.ExtractRegisteredDomain(flow.Host) == targetRD
	}
}

// filterDefenseMatches drops infra-only signals from each match, recomputes
// confidence from the survivors, and discards any vendor left with no
// defense-implying signal.
func filterDefenseMatches(in []model.VendorMatch) []model.VendorMatch {
	var out []model.VendorMatch
	for _, m := range in {
		kept := m.Signals[:0:0]
		best := ""
		for _, label := range m.Signals {
			if !defenseSignalAllowed(label) {
				continue
			}
			kept = append(kept, label)
			if conf := strings.SplitN(label, ":", 2)[0]; vendor.BetterConfidence(conf, best) {
				best = conf
			}
		}
		if len(kept) == 0 {
			continue
		}
		out = append(out, model.VendorMatch{Vendor: m.Vendor, Confidence: best, Signals: kept})
	}
	return out
}

// defenseSignalAllowed reports whether a detector label implies an active
// defense. It classifies by the confidence-stripped type:rest key; anything not
// in defenseSignals returns false (safe default: omitted from the panel).
func defenseSignalAllowed(label string) bool {
	parts := strings.SplitN(label, ":", 2)
	if len(parts) != 2 {
		return false
	}
	return defenseSignals[parts[1]]
}

// mergeDefenses dedupes by vendor, keeping the best confidence seen.
func mergeDefenses(into map[string]model.VendorMatch, matches []model.VendorMatch) {
	for _, m := range matches {
		if existing, ok := into[m.Vendor]; !ok || vendor.BetterConfidence(m.Confidence, existing.Confidence) {
			into[m.Vendor] = m
		}
	}
}

// sortedDefenses flattens the accumulator map into a slice sorted by vendor name.
func sortedDefenses(into map[string]model.VendorMatch) []model.VendorMatch {
	if len(into) == 0 {
		return nil
	}
	out := make([]model.VendorMatch, 0, len(into))
	for _, m := range into {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

// isAntibot reports whether a classification marks the flow as anti-bot traffic.
func isAntibot(c model.ClassifyResult) bool {
	return c.Category == model.Antibot || hasSignal(c, "antibot_js")
}

func hasSignal(c model.ClassifyResult, want string) bool {
	for _, s := range c.Signals {
		if s == want {
			return true
		}
	}
	return false
}

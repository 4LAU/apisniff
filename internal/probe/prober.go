package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/vendor"
	"github.com/enetx/g"
	"github.com/enetx/surf"
)

const (
	chromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
	firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0"
	botUA     = "apisniff-go/0.1"
)

type Options struct {
	Proxy       string
	Headers     map[string]string
	Cookie      string
	Insecure    bool
	Impersonate string
	Timeout     time.Duration
}

func Run(ctx context.Context, target string, opts Options) (*model.ProbeAssessment, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	target = normalizeTargetURL(target)

	// The impersonated probe must send a User-Agent matching its TLS profile.
	// A Firefox fingerprint paired with a Chrome UA is an incoherent client
	// signature that fingerprint-consistency defenses flag, skewing the verdict.
	impersonatedUA := chromeUA
	if strings.EqualFold(opts.Impersonate, "firefox") {
		impersonatedUA = firefoxUA
	}
	variants := []struct {
		name string
		fn   func(context.Context, string, Options) model.ProbeResult
	}{
		{"naked", rawProbe(botUA)},
		{"impersonated", surfProbe(impersonatedUA)},
		{"tls_only", surfProbe(botUA)},
	}

	results := make([]model.ProbeResult, len(variants))
	var wg sync.WaitGroup
	for i, variant := range variants {
		wg.Add(1)
		go func(i int, variantName string, fn func(context.Context, string, Options) model.ProbeResult) {
			defer wg.Done()
			result := fn(ctx, target, opts)
			result.Variant = variantName
			results[i] = result
		}(i, variant.name, variant.fn)
	}
	wg.Wait()

	detector, err := vendor.NewDetector()
	if err != nil {
		return nil, err
	}
	vendorsByName := map[string]model.VendorMatch{}
	for _, result := range results {
		for _, match := range detector.Match(result.Headers, result.Body, result.Status) {
			existing, ok := vendorsByName[match.Vendor]
			if !ok || vendor.BetterConfidence(match.Confidence, existing.Confidence) {
				vendorsByName[match.Vendor] = match
			}
		}
	}
	vendors := make([]model.VendorMatch, 0, len(vendorsByName))
	for _, match := range vendorsByName {
		vendors = append(vendors, match)
	}
	sort.Slice(vendors, func(i, j int) bool {
		return vendors[i].Vendor < vendors[j].Vendor
	})

	graphql := DetectGraphQL(ctx, target, opts)
	verdict, recommendation := Classify(results, vendors)
	return &model.ProbeAssessment{
		URL:            target,
		Verdict:        verdict,
		Recommendation: recommendation,
		Results:        results,
		Vendors:        vendors,
		GraphQL:        graphql,
	}, nil
}

func rawProbe(userAgent string) func(context.Context, string, Options) model.ProbeResult {
	return func(ctx context.Context, target string, opts Options) model.ProbeResult {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec
		}
		defer transport.CloseIdleConnections()
		if opts.Proxy != "" {
			proxyURL, err := url.Parse(opts.Proxy)
			if err != nil {
				return model.ProbeResult{Error: fmt.Sprintf("invalid proxy URL: %v", err)}
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		return doHTTP(ctx, &http.Client{Timeout: opts.Timeout, Transport: transport}, target, userAgent, opts)
	}
}

func surfProbe(userAgent string) func(context.Context, string, Options) model.ProbeResult {
	return func(ctx context.Context, target string, opts Options) model.ProbeResult {
		builder := surf.NewClient().Builder().Timeout(opts.Timeout)
		if opts.Proxy != "" {
			builder = builder.Proxy(g.String(opts.Proxy))
		}
		// surf defaults to InsecureSkipVerify=true; honor --insecure exactly as
		// replay's newHTTPClient does instead of always skipping verification.
		if !opts.Insecure {
			builder = builder.SecureTLS()
		}
		// Same profiles and same rejection of unknown values as replay's
		// newHTTPClient, so --impersonate means one thing across commands.
		impersonate := builder.Impersonate()
		switch strings.ToLower(opts.Impersonate) {
		case "chrome", "":
			builder = impersonate.Chrome()
		case "firefox":
			builder = impersonate.Firefox()
		default:
			return model.ProbeResult{Error: fmt.Sprintf("unsupported impersonate profile %q", opts.Impersonate)}
		}
		client, err := builder.Build().Result()
		if err != nil {
			return model.ProbeResult{Error: fmt.Sprintf("surf client build failed: %v", err)}
		}
		defer client.CloseIdleConnections()
		return doHTTP(ctx, client.Std(), target, userAgent, opts)
	}
}

func doHTTP(ctx context.Context, client *http.Client, target, userAgent string, opts Options) model.ProbeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return model.ProbeResult{Latency: time.Since(start), Error: err.Error()}
	}
	req.Header.Set("user-agent", userAgent)
	if opts.Cookie != "" {
		req.Header.Set("cookie", opts.Cookie)
	}
	for key, value := range opts.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return model.ProbeResult{Latency: time.Since(start), Error: err.Error()}
	}
	defer resp.Body.Close()
	body, readErr := readLimited(resp.Body, 1024*1024)
	result := model.ProbeResult{
		Status:  resp.StatusCode,
		Latency: time.Since(start),
		Headers: flattenHeaders(resp.Header),
		Body:    body,
	}
	if readErr != nil {
		result.Error = readErr.Error()
	}
	return result
}

func Classify(results []model.ProbeResult, vendors []model.VendorMatch) (model.ProbeVerdict, string) {
	byName := map[string]model.ProbeResult{}
	for _, result := range results {
		byName[result.Variant] = result
	}
	naked := byName["naked"]
	impersonated := byName["impersonated"]
	tlsOnly := byName["tls_only"]

	allBlocked := naked.IsBlocked() && impersonated.IsBlocked() && tlsOnly.IsBlocked()
	allConnError := naked.IsConnError() && impersonated.IsConnError() && tlsOnly.IsConnError()
	allPass := naked.Status > 0 && impersonated.Status > 0 && tlsOnly.Status > 0 && !naked.IsBlocked() && !impersonated.IsBlocked() && !tlsOnly.IsBlocked()
	allChallenge := naked.IsChallenge() && impersonated.IsChallenge() && tlsOnly.IsChallenge()
	anyChallenge := naked.IsChallenge() || impersonated.IsChallenge() || tlsOnly.IsChallenge()
	vendorPrefix := ""
	if len(vendors) > 0 {
		names := make([]string, 0, len(vendors))
		for _, match := range vendors {
			names = append(names, strings.ReplaceAll(match.Vendor, "_", " "))
		}
		vendorPrefix = strings.Join(names, ", ") + ": "
	}

	if allConnError {
		return model.ClientDependent, vendorPrefix + "all probe attempts failed with network errors; verify target URL, DNS, proxy, or connectivity."
	} else if allPass {
		return model.NoProtection, vendorPrefix + "no active defenses detected; raw HTTP requests sufficient."
	}
	if allChallenge {
		return model.JSChallenge, vendorPrefix + "JavaScript challenges on all probe types; use recon."
	}
	if allBlocked {
		return model.FullBlock, vendorPrefix + "all probe types blocked; use a full browser session."
	}
	if naked.IsBlocked() && !impersonated.IsBlocked() {
		if tlsOnly.IsBlocked() {
			return model.ClientDependent, vendorPrefix + "filtering by TLS fingerprint and user-agent."
		}
		return model.ClientDependent, vendorPrefix + "filtering by TLS fingerprint."
	}
	if anyChallenge {
		return model.ClientDependent, vendorPrefix + "selective challenge behavior based on client signals."
	}
	return model.ClientDependent, vendorPrefix + "mixed probe results across client variants."
}

func flattenHeaders(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		lower := strings.ToLower(key)
		if lower == "set-cookie" {
			out[lower] = strings.Join(values, "\n")
		} else {
			out[lower] = strings.Join(values, ", ")
		}
	}
	return out
}

func normalizeTargetURL(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "https://" + raw
}

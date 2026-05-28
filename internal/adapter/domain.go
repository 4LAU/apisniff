package adapter

import (
	"net/url"
	"sort"

	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/model"
)

type DomainDetection struct {
	Domain      string
	Count       int
	SecondCount int
	Ambiguous   bool
}

func AutoDetectDomain(flows []model.CapturedFlow) DomainDetection {
	counts := map[string]int{}
	for _, flow := range flows {
		host := flow.Host
		if host == "" && flow.URL != "" {
			if parsed, err := url.Parse(flow.URL); err == nil {
				host = parsed.Hostname()
			}
		}
		domain := classify.ExtractRegisteredDomain(host)
		if domain != "" {
			counts[domain]++
		}
	}
	if len(counts) == 0 {
		return DomainDetection{}
	}
	type pair struct {
		domain string
		count  int
	}
	pairs := make([]pair, 0, len(counts))
	for domain, count := range counts {
		pairs = append(pairs, pair{domain: domain, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].domain < pairs[j].domain
		}
		return pairs[i].count > pairs[j].count
	})
	result := DomainDetection{Domain: pairs[0].domain, Count: pairs[0].count}
	if len(pairs) > 1 {
		result.SecondCount = pairs[1].count
		result.Ambiguous = result.Count < 2*result.SecondCount
	}
	return result
}


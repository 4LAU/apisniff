package classify

import _ "embed"

//go:embed signatures/challenge_indicators.yaml
var challengeIndicatorsYAML []byte

//go:embed signatures/noise_domains.yaml
var noiseDomainsYAML []byte

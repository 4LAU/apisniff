module github.com/4LAU/apisniff

go 1.26

toolchain go1.26.5

require (
	charm.land/lipgloss/v2 v2.0.5
	github.com/charmbracelet/colorprofile v0.4.3
	github.com/charmbracelet/x/term v0.2.2
	github.com/chromedp/cdproto v0.0.0-20260719223732-95f6af754cfe
	github.com/chromedp/chromedp v0.16.0
	// Do not upgrade to v1.8.5: it coalesces the response head into one
	// buffered write (upstream PR #787), so a small flushed chunk never
	// reaches the client and internal/capture's streaming tests hang.
	github.com/elazarl/goproxy v1.8.4
	// Do not upgrade enetx/g or enetx/surf: newer releases rewrite go.mod to
	// go 1.27, above this module's pinned go 1.26 / toolchain go1.26.5.
	github.com/enetx/g v1.0.224
	github.com/enetx/surf v1.0.200
	github.com/getkin/kin-openapi v0.142.0
	github.com/gobwas/ws v1.4.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/net v0.57.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20251205161215-1948445e3318 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/enetx/http v1.0.28 // indirect
	github.com/enetx/http2 v1.0.26 // indirect
	github.com/enetx/http3 v1.0.7 // indirect
	github.com/enetx/iter v0.0.0-20250912135656-f1583323588f // indirect
	github.com/go-json-experiment/json v0.0.0-20260623181947-01eb4420fa68 // indirect
	github.com/go-openapi/jsonpointer v0.22.5 // indirect
	github.com/go-openapi/swag/jsonname v0.25.5 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/oasdiff/yaml v0.1.1 // indirect
	github.com/oasdiff/yaml3 v0.0.14 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/wzshiming/socks5 v0.7.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

package capture

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/4LAU/apisniff/internal/classify"
	"github.com/4LAU/apisniff/internal/finalize"
	"github.com/4LAU/apisniff/internal/model"
	"github.com/4LAU/apisniff/internal/vendor"
	"github.com/elazarl/goproxy"
)

const proxyBodyLimit = 5 * 1024 * 1024

type proxyRequestState struct {
	flow    model.CapturedFlow
	reqBody *captureReader
}

func CaptureProxy(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.LaunchBrowser {
		if _, ok := ChromeAvailable(); !ok {
			return nil, fmt.Errorf("Chrome not found; install Chrome or Chromium, or rerun with --no-browser")
		}
	}
	// Bind/allowlist validation is authoritative here (the CLI can be bypassed):
	// reject IPv6 binds and an allowlist paired with a loopback bind before any
	// port is opened.
	bindHost, isLoopback, allowed, err := normalizeBind(cfg)
	if err != nil {
		return nil, err
	}
	// A launched Chrome dials the proxy from this same host. When the bind is a
	// specific LAN IP, Chrome must dial that IP and its self-connection arrives
	// from the bind IP — neither loopback nor (necessarily) in the allowlist — so
	// include the bind host among the allowed sources before the listener wraps
	// it (done before Serve starts, so no concurrent map access). Computed here
	// rather than at launch so the same value feeds LaunchCleanBrowser below.
	chromeTargetHost := chromeProxyTarget(bindHost)
	allowed = allowlistForListener(allowed, bindHost, cfg.LaunchBrowser)
	// No-browser callers (CLI --no-browser AND direct library callers) need a
	// stable, knowable endpoint to point their own client at; default to 8080.
	// A launched browser is pointed at whatever port we bind, so it can be
	// ephemeral — leave Port==0 to bind 127.0.0.1:0 below.
	if cfg.Port == 0 && !cfg.LaunchBrowser {
		cfg.Port = 8080
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if cfg.URL == "" {
		cfg.URL = "https://" + cfg.Domain
	}
	start := time.Now()
	bundle, err := NewBundleDir(cfg.Domain, start)
	if err != nil {
		return nil, err
	}
	flowsPath := filepath.Join(bundle, "flows.jsonl")
	writer, err := NewJSONLWriter(flowsPath)
	if err != nil {
		return nil, err
	}
	writerClosed := false
	defer func() {
		if !writerClosed {
			_ = writer.Close()
		}
	}()
	filtered := newLazyFilteredWriter(bundle)
	defer filtered.Close()

	caPath, spkiHash, err := EnsureProxyCA(cfg.StatusWriter)
	if err != nil {
		return nil, err
	}
	classifier, err := classify.New(cfg.Domain)
	if err != nil {
		return nil, err
	}
	// The defense panel is fail-soft: a signature-load failure must never abort
	// browser capture, so we log and continue with det == nil.
	det, err := vendor.NewDetector()
	if err != nil {
		if cfg.StatusWriter != nil {
			fmt.Fprintf(cfg.StatusWriter, "defense detection disabled: %v\n", err)
		}
		det = nil
	}
	targetRD := classify.ExtractRegisteredDomain(cfg.Domain)

	var mu sync.Mutex
	var flowCount atomic.Int64
	var activeWG sync.WaitGroup
	stats := model.SessionStats{
		Domain:    cfg.Domain,
		StartedAt: start.UTC().Format(time.RFC3339),
		Dropped:   map[string]int{},
	}
	defenses := map[string]model.VendorMatch{}
	var unattributedAntibot int
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Logger = log.New(io.Discard, "", 0)
	proxy.AllowHTTP2 = true
	proxy.CertStore = &certCache{}
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	recordFlow := func(flow model.CapturedFlow) {
		classification, kept := classifier.Classify(flow)
		// det.Match lowercases up to 500KB of body; run it outside mu so the
		// shared lock only covers the cheap accumulation below.
		matches, scoped := detectDefenses(det, targetRD, flow, classification)
		mu.Lock()
		defer mu.Unlock()
		mergeDefenses(defenses, matches)
		if scoped && isAntibot(classification) && len(matches) == 0 {
			unattributedAntibot++
		}
		stats.TotalFlows++
		flowCount.Add(1)
		if classification.Action == "drop" || kept == nil {
			dropKey := classification.Reason
			if dropKey == "" {
				dropKey = string(classification.Category)
			}
			stats.Dropped[dropKey]++
			if classification.Action == "drop" {
				filtered.Write(flow, classification)
			}
			return
		}
		if err := writer.Write(*kept); err != nil {
			stats.Dropped["write_error"]++
			return
		}
		stats.KeptFlows = writer.Count()
	}

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, pctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		flow, err := flowFromProxyRequest(req)
		if err != nil {
			pctx.UserData = err
			return req, nil
		}
		state := &proxyRequestState{flow: flow}
		if req.Body != nil && req.Body != http.NoBody {
			// Record the request body as the transport streams it upstream —
			// no pre-read, no temp file. The snapshot is taken when the
			// response body finishes.
			state.reqBody = newCaptureReader(req.Body, proxyBodyLimit)
			req.Body = state.reqBody
		}
		pctx.UserData = state
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, pctx *goproxy.ProxyCtx) *http.Response {
		state, ok := pctx.UserData.(*proxyRequestState)
		if !ok || resp == nil {
			return resp
		}
		flow := state.flow
		flow.ResponseStatus = resp.StatusCode
		flow.ResponseHeaders = headersToMap(resp.Header)
		flow.Tags = appendTag(flow.Tags, "request_proto:"+flowProto(pctx.Req))
		flow.Tags = appendTag(flow.Tags, "upstream_response_proto:"+resp.Proto)
		reqBody := state.reqBody
		finalize := func(body []byte, truncated, complete bool, readErr error) {
			if reqBody != nil {
				captured, reqTruncated, reqComplete, reqErr := reqBody.snapshot()
				if reqErr != nil {
					flow.Tags = appendTag(flow.Tags, "request_body_error")
				} else {
					flow.RequestBody = captured
					if reqTruncated {
						flow.Tags = appendTag(flow.Tags, "request_body_truncated")
					}
					// The server can respond before draining the upload
					// (HTTP/2, early 4xx); the captured prefix is then not
					// the full request body.
					if !reqComplete {
						flow.Tags = appendTag(flow.Tags, "request_body_incomplete")
					}
				}
			}
			if readErr != nil {
				flow.Tags = appendTag(flow.Tags, "response_body_error")
			} else {
				flow.ResponseBody = body
				if truncated {
					flow.Tags = appendTag(flow.Tags, "response_body_truncated")
				}
				if !complete {
					flow.Tags = appendTag(flow.Tags, "response_body_incomplete")
				}
			}
			recordFlow(flow)
		}
		if resp.Body == nil {
			finalize(nil, false, true, nil)
			return resp
		}
		// The body streams through to the client unbuffered; the flow is
		// recorded once the body completes (EOF) or the client goes away
		// (Close). A streaming/SSE response therefore reaches the client
		// immediately instead of stalling until fully read.
		activeWG.Add(1)
		wrappedFinalize := func(body []byte, truncated, complete bool, readErr error) {
			defer activeWG.Done()
			finalize(body, truncated, complete, readErr)
		}
		resp.Body = newFinalizingBody(resp.Body, proxyBodyLimit, wrappedFinalize)
		return resp
	})

	server := &http.Server{Handler: proxy}
	listener, err := net.Listen("tcp", net.JoinHostPort(bindHost, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, err
	}
	cfg.Port = listener.Addr().(*net.TCPAddr).Port // resolve ephemeral → actual
	server.Addr = listener.Addr().String()
	// Off-loopback binds may carry a source-IP allowlist. A rejected connection
	// is closed and the loop keeps serving, so a stranger never takes the proxy
	// down. Loopback is always allowed so the launched Chrome is never denied.
	if len(allowed) > 0 {
		listener = &allowlistListener{Listener: listener, allowed: allowed}
	}
	runCtx, stopSignals := signal.NotifyContext(ctx, gracefulSignals...)
	defer stopSignals()
	runCtx, cancelTimeout := context.WithTimeout(runCtx, cfg.Timeout)
	defer cancelTimeout()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	if cfg.LaunchBrowser {
		// Fresh, disposable profile per run — wiped when capture finishes, so no
		// login credentials persist on disk.
		profileDir, err := os.MkdirTemp("", "apisniff-chrome-*")
		if err != nil {
			shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelShutdown()
			if err := server.Shutdown(shutdownCtx); err != nil {
				_ = server.Close()
			}
			<-errCh
			return nil, err
		}
		defer os.RemoveAll(profileDir)
		// Chrome accepts the proxy's MITM leaf certs via the SPKI-list flag
		// (computed from the CA in hand each run). This needs no OS trust store
		// change — no permanently trusted root, no keychain prompt, no platform
		// subprocess. Chrome shows a cosmetic "unsupported flag" infobar (browser
		// UI only, invisible to pages, so the no-fingerprint property holds).
		if cfg.StatusWriter != nil {
			fmt.Fprintf(cfg.StatusWriter, "MITM proxy listening on %s\n", server.Addr)
			fmt.Fprintf(cfg.StatusWriter, "Launching Chrome (fresh profile, no automation flags) through proxy...\n")
			fmt.Fprintf(cfg.StatusWriter, "Chrome will show a yellow \"unsupported flag\" warning bar at the top — that's expected and safe to ignore.\n")
			fmt.Fprintf(cfg.StatusWriter, "Log in and use the site. When done: close the browser window, or press Ctrl+C here.\n")
			if !isLoopback {
				writeNonLoopbackSetup(cfg.StatusWriter, bindHost, cfg.Port, allowed)
			}
		}
		cmd, err := LaunchCleanBrowser(runCtx, net.JoinHostPort(chromeTargetHost, strconv.Itoa(cfg.Port)), spkiHash, profileDir, cfg.URL, cfg.Headless)
		if err != nil {
			shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelShutdown()
			if err := server.Shutdown(shutdownCtx); err != nil {
				_ = server.Close()
			}
			<-errCh
			return nil, fmt.Errorf("failed to launch Chrome: %w", err)
		}

		showStatus := cfg.StatusWriter != nil && isTerminal(cfg.StatusWriter)
		var status *statusLine
		if showStatus {
			status = newStatusLine(cfg.StatusWriter, "Capturing traffic", &flowCount)
			status.start()
		}

		// End the session when the user closes the last Chrome window/tab (⌘W,
		// detected via renderer processes), quits Chrome outright (the process
		// exits), or on timeout/signal — runCtx cancellation makes CommandContext
		// kill Chrome, so cmd.Wait returns either way.
		browserDone := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(browserDone)
		}()
		pagesClosed := watchAllPagesClosed(runCtx, cmd.Process.Pid)
		select {
		case <-browserDone:
		case <-pagesClosed:
			_ = cmd.Process.Kill()
			<-browserDone
		case <-runCtx.Done():
			<-browserDone
		}

		if status != nil {
			status.stop()
		}

		// Drain period: wait for in-flight finalizers (max 500ms)
		drainDone := make(chan struct{})
		go func() {
			activeWG.Wait()
			close(drainDone)
		}()
		select {
		case <-drainDone:
		case <-time.After(500 * time.Millisecond):
		}
	} else {
		if cfg.StatusWriter != nil {
			fmt.Fprintf(cfg.StatusWriter, "MITM proxy listening on %s\n", server.Addr)
			fmt.Fprintf(cfg.StatusWriter, "CA certificate: %s\n", caPath)
			fmt.Fprintf(cfg.StatusWriter, "SPKI hash: %s\n", spkiHash)
			if isLoopback {
				// server.Addr is a real, dialable loopback endpoint here.
				fmt.Fprintf(cfg.StatusWriter, "Configure your client to proxy through %s and trust the CA above.\n", server.Addr)
			} else {
				// Off-loopback, server.Addr prints 0.0.0.0:<port> (or a LAN IP),
				// which is not a usable device proxy target — print real targets.
				writeNonLoopbackSetup(cfg.StatusWriter, bindHost, cfg.Port, allowed)
			}
		}
		showStatus := cfg.StatusWriter != nil && isTerminal(cfg.StatusWriter)
		if showStatus {
			status := newStatusLine(cfg.StatusWriter, "Capturing traffic", &flowCount)
			status.start()
			<-runCtx.Done()
			status.stop()
		} else {
			<-runCtx.Done()
		}

		// Drain period: wait for in-flight finalizers (max 500ms)
		drainDone := make(chan struct{})
		go func() {
			activeWG.Wait()
			close(drainDone)
		}()
		select {
		case <-drainDone:
		case <-time.After(500 * time.Millisecond):
		}
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	// A straggler connection must not cost the user the capture: if graceful
	// shutdown cannot drain within the grace period, force-close and keep
	// the bundle.
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
	}
	if err := <-errCh; err != nil && err != http.ErrServerClosed {
		return nil, err
	}
	// Hijacked MITM connections are not waited on by Shutdown, so a
	// streaming response can still finalize after this point. Close the
	// writers and snapshot the stats under the same lock finalize uses;
	// stragglers then fail cleanly against the closed writer.
	mu.Lock()
	stats.DurationSeconds = time.Since(start).Seconds()
	resultFilteredPath := filtered.Close()
	writerClosed = true
	closeErr := writer.Close()
	stats.Defenses = sortedDefenses(defenses)
	stats.UnattributedAntibot = unattributedAntibot
	statsCopy := stats
	statsCopy.Dropped = make(map[string]int, len(stats.Dropped))
	for key, count := range stats.Dropped {
		statsCopy.Dropped[key] = count
	}
	mu.Unlock()
	if closeErr != nil {
		return nil, closeErr
	}
	if err := WriteSession(bundle, statsCopy); err != nil {
		return nil, err
	}
	// Non-fatal: capture already succeeded. Co-locate spec + private catalog.
	gqlSummary := finalize.FromBundle(bundle, flowsPath, statsCopy.Domain)
	return &Result{BundleDir: bundle, FlowsPath: flowsPath, FilteredPath: resultFilteredPath, CAPath: caPath, SPKIHash: spkiHash, Stats: statsCopy, GraphQL: gqlSummary}, nil
}

// normalizeBind resolves cfg.BindHost (empty/"localhost" → 127.0.0.1), rejects
// IPv6, folds an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its dotted-quad
// form, validates each cfg.AllowedClients entry parses as an IP, and rejects an
// allowlist paired with a loopback bind. It returns the resolved bind host,
// whether it is loopback, and the allowlist keyed by normalized IP string (so
// "192.168.0.5" matches regardless of formatting). Extracted from CaptureProxy
// so the validation is unit-testable without launching Chrome.
func normalizeBind(cfg Config) (bindHost string, isLoopback bool, allowed map[string]bool, err error) {
	bindHost = cfg.BindHost
	if bindHost == "" || bindHost == "localhost" {
		bindHost = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(bindHost)
	if err != nil {
		return "", false, nil, fmt.Errorf("invalid --bind address %q: %w", bindHost, err)
	}
	if addr.Is6() && !addr.Is4In6() {
		return "", false, nil, errors.New("IPv6 bind addresses are not supported")
	}
	// An IPv4-mapped IPv6 address (::ffff:a.b.c.d) slips past the IPv6 gate
	// above; fold it to its clean dotted-quad form so every downstream use
	// (listener bind, warning output, device targets) sees a plain IPv4 instead
	// of a bracketed literal. Compute isLoopback from the unmapped addr too.
	if addr.Is4In6() {
		addr = addr.Unmap()
		bindHost = addr.String()
	}
	isLoopback = addr.IsLoopback()
	allowed = make(map[string]bool)
	for _, raw := range cfg.AllowedClients {
		client, parseErr := netip.ParseAddr(raw)
		if parseErr != nil {
			return "", false, nil, fmt.Errorf("invalid --allow-client address %q: %w", raw, parseErr)
		}
		// Fold IPv4-mapped IPv6 (::ffff:a.b.c.d) to its dotted-quad form so the
		// key matches the unmapped form compared in Accept; otherwise a mapped
		// --allow-client entry would never match a plain-IPv4 remote.
		allowed[client.Unmap().String()] = true
	}
	if len(allowed) > 0 && isLoopback {
		return "", false, nil, errors.New("--allow-client only applies when --bind is a non-loopback address")
	}
	return bindHost, isLoopback, allowed, nil
}

// isSpecificBindIP reports whether bindHost is a concrete LAN IP — one that
// parses and is neither loopback nor the unspecified 0.0.0.0. Loopback and
// unspecified binds are reachable on this host via 127.0.0.1; a specific IP is
// not, which is what the Chrome-target, allowlist, and device-target logic key
// on. Centralizing the predicate keeps those three in lockstep.
func isSpecificBindIP(bindHost string) bool {
	addr, err := netip.ParseAddr(bindHost)
	return err == nil && !addr.IsLoopback() && !addr.IsUnspecified()
}

// chromeProxyTarget picks the host a launched Chrome (on this same machine)
// dials to reach the proxy: the specific bind host when it is a concrete LAN IP
// (reachable from the same host), otherwise 127.0.0.1 (a loopback or 0.0.0.0
// bind both answer on loopback). Pure so the selection is unit-testable without
// launching Chrome.
func chromeProxyTarget(bindHost string) string {
	if isSpecificBindIP(bindHost) {
		return bindHost
	}
	return "127.0.0.1"
}

// allowlistForListener returns the allowlist the allowlistListener should enforce.
// When a browser is launched against a specific-IP bind, Chrome's self-connection
// arrives from the bind IP — neither loopback nor in the user's allowlist — so
// the bind host is added to keep that connection from being rejected. Loopback
// and unspecified binds keep Chrome on 127.0.0.1 (always allowed), and the no-
// allowlist / no-browser cases are returned unchanged. It never mutates its input
// so it is unit-testable as a pure function.
func allowlistForListener(allowed map[string]bool, bindHost string, launchBrowser bool) map[string]bool {
	if !launchBrowser || len(allowed) == 0 || !isSpecificBindIP(bindHost) {
		return allowed
	}
	out := make(map[string]bool, len(allowed)+1)
	for ip := range allowed {
		out[ip] = true
	}
	out[bindHost] = true
	return out
}

// allowlistListener wraps a net.Listener and silently drops connections whose
// source IP is neither loopback nor in the allowlist. Accept loops until a
// permitted connection arrives (or the underlying listener errors), so a
// rejected connection never surfaces as a Serve error.
type allowlistListener struct {
	net.Listener
	allowed map[string]bool
}

func (l *allowlistListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			_ = conn.Close()
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			_ = conn.Close()
			continue
		}
		// Unmap IPv4-in-IPv6 remotes (a dual-stack kernel may deliver an IPv4
		// peer as ::ffff:a.b.c.d) so the lookup matches the dotted-quad keys
		// stored by normalizeBind.
		ip = ip.Unmap()
		if ip.IsLoopback() || l.allowed[ip.String()] {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// ifaceAddrs pairs an interface's flags with its addresses so filterLANv4 can
// be unit-tested with synthetic data instead of real network interfaces.
type ifaceAddrs struct {
	Flags net.Flags
	Addrs []net.Addr
}

// filterLANv4 returns the IPv4 address strings that are usable as a device proxy
// target: on interfaces that are up, non-loopback, and non-point-to-point, it
// keeps non-loopback, non-link-local IPv4 addresses.
func filterLANv4(ifaces []ifaceAddrs) []string {
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		for _, addr := range iface.Addrs {
			ip := addrToIPv4(addr)
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// usableLANv4 enumerates the host's real LAN-facing IPv4 addresses by delegating
// to the pure filterLANv4 over net.Interfaces().
func usableLANv4() []string {
	realIfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	ifaces := make([]ifaceAddrs, 0, len(realIfaces))
	for _, ri := range realIfaces {
		addrs, err := ri.Addrs()
		if err != nil {
			continue
		}
		ifaces = append(ifaces, ifaceAddrs{Flags: ri.Flags, Addrs: addrs})
	}
	return filterLANv4(ifaces)
}

// addrToIPv4 extracts the IPv4 form of an interface address. net.Interface.Addrs
// returns *net.IPNet values whose String() is CIDR form, so ParseCIDR is the only
// path that matters; a non-CIDR address yields nil.
func addrToIPv4(addr net.Addr) net.IP {
	ip, _, err := net.ParseCIDR(addr.String())
	if err != nil {
		return nil
	}
	return ip.To4()
}

// writeNonLoopbackSetup prints the security warning and device-proxy setup for a
// non-loopback bind: a prominent exposure warning, the concrete Wi-Fi proxy
// target(s) to enter on the device, and the allowlist (if any).
func writeNonLoopbackSetup(w io.Writer, bindHost string, port int, allowed map[string]bool) {
	warning := fmt.Sprintf("WARNING: proxy is exposed on the network (%s:%d). ", bindHost, port)
	if len(allowed) == 0 {
		warning += "Anyone on this network can route traffic through it; "
	}
	warning += "press Ctrl+C when done."
	fmt.Fprintln(w, warning)
	for _, ip := range deviceProxyTargets(bindHost, usableLANv4()) {
		fmt.Fprintf(w, "Set your device's Wi-Fi proxy to %s:%d\n", ip, port)
	}
	if len(allowed) > 0 {
		ips := make([]string, 0, len(allowed))
		for ip := range allowed {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		fmt.Fprintf(w, "Allowed clients: %s\n", strings.Join(ips, ", "))
	}
}

// deviceProxyTargets returns the concrete IP(s) a remote device should enter as
// its Wi-Fi proxy: the bind host itself when it is a specific IP, or every
// usable LAN IPv4 in lanIPs (enumerated by the caller via usableLANv4) when
// bound to the unspecified 0.0.0.0. lanIPs is passed in so the selection stays a
// pure, unit-testable function.
func deviceProxyTargets(bindHost string, lanIPs []string) []string {
	if isSpecificBindIP(bindHost) {
		return []string{bindHost}
	}
	out := append([]string(nil), lanIPs...)
	sort.Strings(out)
	return out
}

func EnsureProxyCA(status io.Writer) (string, string, error) {
	dir, err := proxyConfigDir()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if certPEM, certErr := os.ReadFile(certPath); certErr == nil {
		if keyPEM, keyErr := os.ReadFile(keyPath); keyErr == nil {
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err == nil {
				cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
				if reason := validateCA(&cert); reason != "" {
					if status != nil {
						fmt.Fprintf(status, "existing CA at %s is invalid (%s); generating a new one\n", certPath, reason)
					}
				} else {
					goproxy.GoproxyCa = cert
					return certPath, SPKIHash(cert.Leaf), nil
				}
			}
		}
	}
	certPEM, keyPEM, cert, err := generateProxyCA()
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	goproxy.GoproxyCa = cert
	return certPath, SPKIHash(cert.Leaf), nil
}

func validateCA(cert *tls.Certificate) string {
	leaf := cert.Leaf
	if leaf == nil {
		return "no leaf certificate"
	}
	if !leaf.IsCA {
		return "not a CA"
	}
	if !leaf.BasicConstraintsValid {
		return "BasicConstraintsValid is false"
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		return "missing KeyUsageCertSign"
	}
	if time.Now().After(leaf.NotAfter) {
		return "certificate has expired"
	}
	switch cert.PrivateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		// supported
	default:
		return "unsupported private key type"
	}
	return ""
}

func generateProxyCA() ([]byte, []byte, tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"apisniff local MITM"},
			CommonName:   "apisniff local MITM CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	cert.Leaf, _ = x509.ParseCertificate(der)
	return certPEM, keyPEM, cert, nil
}

func proxyConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".apisniff"), nil
}

// SPKIHash returns the base64-encoded SHA-256 hash of the certificate's
// Subject Public Key Info (SPKI). This is the format used by Chrome's
// --ignore-certificate-errors-spki-list flag.
func SPKIHash(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

// certCache implements goproxy.CertStorage, caching generated leaf certs by
// hostname so each host's cert is only generated once per session.
type certCache struct {
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func (c *certCache) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache != nil {
		if cert, ok := c.cache[hostname]; ok {
			return cert, nil
		}
	}
	cert, err := gen()
	if err != nil {
		return nil, err
	}
	if c.cache == nil {
		c.cache = make(map[string]*tls.Certificate)
	}
	c.cache[hostname] = cert
	return cert, nil
}

func flowFromProxyRequest(req *http.Request) (model.CapturedFlow, error) {
	rawURL := req.URL.String()
	if !req.URL.IsAbs() {
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		rawURL = scheme + "://" + req.Host + req.URL.RequestURI()
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return model.CapturedFlow{}, err
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	host := strings.ToLower(parsed.Hostname())
	flow := model.NewCapturedFlow(req.Method, rawURL, host, path)
	flow.RequestHeaders = headersToMap(req.Header)
	flow.Tags = appendTag(flow.Tags, "request_proto:"+flowProto(req))
	return flow, nil
}

func flowProto(req *http.Request) string {
	if req == nil {
		return ""
	}
	return req.Proto
}

func headersToMap(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		out[strings.ToLower(key)] = strings.Join(values, "\n")
	}
	return out
}

// captureReader tees a body stream into a size-capped in-memory buffer as the
// real consumer reads it. It never pre-reads and never touches disk, so the
// stream's pacing is untouched.
type captureReader struct {
	rc    io.ReadCloser
	limit int64

	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
	sawEOF    bool
	readErr   error
}

func newCaptureReader(rc io.ReadCloser, limit int64) *captureReader {
	return &captureReader{rc: rc, limit: limit}
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.mu.Lock()
	if n > 0 {
		remaining := c.limit - int64(c.buf.Len())
		switch {
		case remaining >= int64(n):
			c.buf.Write(p[:n])
		case remaining > 0:
			c.buf.Write(p[:remaining])
			c.truncated = true
		default:
			c.truncated = true
		}
	}
	if err == io.EOF {
		c.sawEOF = true
	} else if err != nil && c.readErr == nil {
		c.readErr = err
	}
	c.mu.Unlock()
	return n, err
}

func (c *captureReader) Close() error {
	return c.rc.Close()
}

func (c *captureReader) snapshot() (body []byte, truncated, complete bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...), c.truncated, c.sawEOF, c.readErr
}

// finalizingBody invokes finalize exactly once when the response body
// completes (EOF) or is closed (client done or gone). finalize receives the
// captured prefix, whether it was truncated at the cap, whether the upstream
// stream completed, and any upstream read error.
type finalizingBody struct {
	*captureReader
	once     sync.Once
	finalize func(body []byte, truncated, complete bool, readErr error)
}

func newFinalizingBody(rc io.ReadCloser, limit int64, finalize func(body []byte, truncated, complete bool, readErr error)) *finalizingBody {
	return &finalizingBody{captureReader: newCaptureReader(rc, limit), finalize: finalize}
}

func (f *finalizingBody) Read(p []byte) (int, error) {
	n, err := f.captureReader.Read(p)
	if err != nil {
		f.fire()
	}
	return n, err
}

func (f *finalizingBody) Close() error {
	err := f.captureReader.Close()
	f.fire()
	return err
}

func (f *finalizingBody) fire() {
	f.once.Do(func() {
		f.finalize(f.snapshot())
	})
}

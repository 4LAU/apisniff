package capture

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNormalizeBindDefaultsToLoopback(t *testing.T) {
	for _, host := range []string{"", "localhost"} {
		bindHost, isLoopback, allowed, err := normalizeBind(Config{BindHost: host})
		if err != nil {
			t.Fatalf("BindHost=%q: unexpected error %v", host, err)
		}
		if bindHost != "127.0.0.1" {
			t.Errorf("BindHost=%q: bindHost = %q, want 127.0.0.1", host, bindHost)
		}
		if !isLoopback {
			t.Errorf("BindHost=%q: isLoopback = false, want true", host)
		}
		if len(allowed) != 0 {
			t.Errorf("BindHost=%q: allowed = %v, want empty", host, allowed)
		}
	}
}

func TestNormalizeBindRejectsIPv6(t *testing.T) {
	for _, host := range []string{"::1", "fe80::1"} {
		_, _, _, err := normalizeBind(Config{BindHost: host})
		if err == nil {
			t.Fatalf("BindHost=%q: expected error, got nil", host)
		}
		if !strings.Contains(err.Error(), "IPv6") {
			t.Fatalf("BindHost=%q: error %q does not mention IPv6", host, err)
		}
	}
}

func TestNormalizeBindAllowlistOnLoopbackErrors(t *testing.T) {
	_, _, _, err := normalizeBind(Config{BindHost: "127.0.0.1", AllowedClients: []string{"192.168.0.5"}})
	if err == nil {
		t.Fatal("expected error for allowlist with loopback bind, got nil")
	}
	if !strings.Contains(err.Error(), "--allow-client") || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("error %q does not explain the misconfig", err)
	}
}

func TestNormalizeBindBadAllowedClientErrors(t *testing.T) {
	_, _, _, err := normalizeBind(Config{BindHost: "0.0.0.0", AllowedClients: []string{"not-an-ip"}})
	if err == nil {
		t.Fatal("expected error for malformed --allow-client, got nil")
	}
	if !strings.Contains(err.Error(), "--allow-client") {
		t.Fatalf("error %q does not mention --allow-client", err)
	}
}

func TestNormalizeBindWildcardWithAllowlist(t *testing.T) {
	bindHost, isLoopback, allowed, err := normalizeBind(Config{BindHost: "0.0.0.0", AllowedClients: []string{"192.168.0.5", "10.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if bindHost != "0.0.0.0" {
		t.Fatalf("bindHost = %q, want 0.0.0.0", bindHost)
	}
	if isLoopback {
		t.Fatal("isLoopback = true, want false for 0.0.0.0")
	}
	if !allowed["192.168.0.5"] || !allowed["10.0.0.1"] || len(allowed) != 2 {
		t.Fatalf("allowed = %v, want {192.168.0.5, 10.0.0.1}", allowed)
	}
}

func TestNormalizeBindSpecificLANIP(t *testing.T) {
	bindHost, isLoopback, _, err := normalizeBind(Config{BindHost: "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	if bindHost != "192.168.1.10" {
		t.Fatalf("bindHost = %q, want 192.168.1.10", bindHost)
	}
	if isLoopback {
		t.Fatal("isLoopback = true for LAN IP")
	}
}

func TestFilterLANv4(t *testing.T) {
	up := net.FlagUp
	ifaces := []ifaceAddrs{
		{Flags: up, Addrs: []net.Addr{stringAddr("192.168.1.5/24")}},                      // included: normal up IPv4
		{Flags: up | net.FlagLoopback, Addrs: []net.Addr{stringAddr("127.0.0.1/8")}},      // excluded: loopback interface
		{Flags: 0, Addrs: []net.Addr{stringAddr("10.0.0.5/24")}},                          // excluded: down interface
		{Flags: up | net.FlagPointToPoint, Addrs: []net.Addr{stringAddr("10.64.0.1/24")}}, // excluded: point-to-point (VPN)
		{Flags: up, Addrs: []net.Addr{stringAddr("169.254.1.1/16")}},                      // excluded: link-local
		{Flags: up, Addrs: []net.Addr{stringAddr("fe80::1/64")}},                          // excluded: IPv6, not IPv4
	}
	got := filterLANv4(ifaces)
	want := []string{"192.168.1.5"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("filterLANv4 = %v, want %v", got, want)
	}
}

func TestAllowlistListenerAcceptsLoopbackAndRejectsOthers(t *testing.T) {
	stranger1 := &scriptConn{remote: "203.0.113.9:1"}
	loopback := &scriptConn{remote: "127.0.0.1:2"}
	stranger2 := &scriptConn{remote: "203.0.113.10:3"}
	permitted := &scriptConn{remote: "192.168.1.50:4"}
	base := &scriptListener{conns: []net.Conn{stranger1, loopback, stranger2, permitted}}
	all := &allowlistListener{Listener: base, allowed: map[string]bool{"192.168.1.50": true}}

	// First Accept: skips+closes stranger1, returns loopback (loopback always allowed,
	// even though 127.0.0.1 is not in the allowlist).
	got, err := all.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got != loopback {
		t.Fatalf("first Accept returned %v, want loopback conn", got)
	}
	if !stranger1.closed {
		t.Error("rejected stranger1 was not closed")
	}

	// Second Accept: skips+closes stranger2, returns the allowlisted conn —
	// proving a rejected connection does not kill the accept loop.
	got, err = all.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got != permitted {
		t.Fatalf("second Accept returned %v, want permitted conn", got)
	}
	if !stranger2.closed {
		t.Error("rejected stranger2 was not closed")
	}
}

func TestCaptureProxyRejectsIPv6Bind(t *testing.T) {
	setTestHome(t, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := CaptureProxy(ctx, Config{Domain: "127.0.0.1", BindHost: "::1", LaunchBrowser: false, Timeout: time.Second})
	if err == nil {
		t.Fatal("expected IPv6 bind to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("error %q does not mention IPv6", err)
	}
}

func TestNormalizeBindIPv4InIPv6(t *testing.T) {
	// ::ffff:a.b.c.d passes the IPv6 gate (it is 4-in-6) but must fold to its
	// dotted-quad form so the listener bind and JoinHostPort never see a bracketed
	// literal.
	bindHost, isLoopback, _, err := normalizeBind(Config{BindHost: "::ffff:192.168.1.10"})
	if err != nil {
		t.Fatalf("unexpected error for IPv4-mapped IPv6: %v", err)
	}
	if bindHost != "192.168.1.10" {
		t.Fatalf("bindHost = %q, want dotted-quad 192.168.1.10", bindHost)
	}
	if joined := net.JoinHostPort(bindHost, "8080"); joined != "192.168.1.10:8080" {
		t.Errorf("JoinHostPort(bindHost, port) = %q, want 192.168.1.10:8080 (no brackets)", joined)
	}
	if isLoopback {
		t.Error("isLoopback = true, want false for 192.168.1.10")
	}
}

func TestChromeProxyTarget(t *testing.T) {
	cases := []struct {
		bind string
		want string
	}{
		{"127.0.0.1", "127.0.0.1"},       // loopback: Chrome dials loopback
		{"0.0.0.0", "127.0.0.1"},         // unspecified: reachable via loopback
		{"192.168.1.10", "192.168.1.10"}, // specific LAN IP: Chrome dials the bind IP
	}
	for _, c := range cases {
		if got := chromeProxyTarget(c.bind); got != c.want {
			t.Errorf("chromeProxyTarget(%q) = %q, want %q", c.bind, got, c.want)
		}
	}
}

func TestAllowlistForListenerIncludesBindHost(t *testing.T) {
	// Specific-IP bind + launched Chrome: the bind host is added so Chrome's
	// self-connection (arriving from the bind IP) is permitted, and the
	// user-allowed client is preserved.
	input := map[string]bool{"10.0.0.5": true}
	got := allowlistForListener(input, "192.168.1.10", true)
	if !got["10.0.0.5"] {
		t.Error("user-allowed client 10.0.0.5 was dropped")
	}
	if !got["192.168.1.10"] {
		t.Error("bind host 192.168.1.10 was not added to the allowlist")
	}
	// Input map is left untouched (the helper must not mutate its caller's map).
	if input["192.168.1.10"] {
		t.Error("allowlistForListener mutated its input map")
	}
}

func TestAllowlistForListenerNoOpCases(t *testing.T) {
	base := map[string]bool{"10.0.0.5": true}
	// Unspecified bind is not a specific IP (Chrome stays on loopback) → no add.
	if got := allowlistForListener(base, "0.0.0.0", true); got["0.0.0.0"] {
		t.Error("unspecified bind should not be added to the allowlist")
	}
	// No browser launched → no add.
	if got := allowlistForListener(base, "192.168.1.10", false); got["192.168.1.10"] {
		t.Error("bind host should not be added when no browser is launched")
	}
	// Empty allowlist → returned unchanged (and still empty).
	if got := allowlistForListener(map[string]bool{}, "192.168.1.10", true); len(got) != 0 {
		t.Errorf("empty allowlist should stay empty, got %v", got)
	}
}

func TestDeviceProxyTargets(t *testing.T) {
	lan := []string{"192.168.1.5", "10.0.0.2"}

	// A specific bind host yields just that host, ignoring enumerated LAN IPs.
	got := deviceProxyTargets("192.168.1.10", lan)
	if len(got) != 1 || got[0] != "192.168.1.10" {
		t.Fatalf("specific-IP deviceProxyTargets = %v, want [192.168.1.10]", got)
	}

	// The unspecified (0.0.0.0) bind enumerates and sorts the LAN IPs.
	got = deviceProxyTargets("0.0.0.0", lan)
	want := []string{"10.0.0.2", "192.168.1.5"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unspecified deviceProxyTargets = %v, want %v", got, want)
	}

	// The caller's slice is not mutated by the internal sort.
	if lan[0] != "192.168.1.5" || lan[1] != "10.0.0.2" {
		t.Fatalf("deviceProxyTargets mutated its input slice: %v", lan)
	}
}

// stringAddr is a minimal net.Addr carrying an opaque string (CIDR or host:port
// form), used to feed synthetic addresses into the pure filters and scripted
// connections without real network interfaces.
type stringAddr string

func (s stringAddr) Network() string { return "ip+net" }
func (s stringAddr) String() string  { return string(s) }

type scriptConn struct {
	remote string
	closed bool
}

func (s *scriptConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (s *scriptConn) Write([]byte) (int, error)        { return 0, errors.New("write not supported") }
func (s *scriptConn) Close() error                     { s.closed = true; return nil }
func (s *scriptConn) LocalAddr() net.Addr              { return stringAddr("0.0.0.0:0") }
func (s *scriptConn) RemoteAddr() net.Addr             { return stringAddr(s.remote) }
func (s *scriptConn) SetDeadline(time.Time) error      { return nil }
func (s *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (s *scriptConn) SetWriteDeadline(time.Time) error { return nil }

type scriptListener struct {
	conns []net.Conn
	next  int
}

func (s *scriptListener) Accept() (net.Conn, error) {
	if s.next >= len(s.conns) {
		// No more scripted conns: a permanent error stops the accept loop.
		return nil, errors.New("script exhausted")
	}
	c := s.conns[s.next]
	s.next++
	return c, nil
}

func (s *scriptListener) Close() error   { return nil }
func (s *scriptListener) Addr() net.Addr { return stringAddr("0.0.0.0:8080") }

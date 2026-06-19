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

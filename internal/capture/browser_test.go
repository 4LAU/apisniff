package capture

import (
	"strings"
	"testing"
)

// The proxy-mode login path must never carry an automation signal — that is the
// whole reason it exists. A bot vendor (DataDome/PerimeterX-class) blocks login
// the instant navigator.webdriver is true or a CDP session is detected, so this
// test pins the absence of those signals.
func TestCleanBrowserArgsNoAutomationSignals(t *testing.T) {
	args := cleanBrowserArgs("127.0.0.1:8080", "SPKIHASH==", "/tmp/profile", "https://example.com", false)
	joined := strings.Join(args, " ")

	for _, banned := range []string{
		"enable-automation",     // sets navigator.webdriver = true
		"remote-debugging-port", // opens a CDP session
		"AutomationControlled",  // only meaningful when fighting an automation flag
		"headless",              // headful by default: real login needs a window
	} {
		if strings.Contains(joined, banned) {
			t.Errorf("clean launch must not contain %q; got: %s", banned, joined)
		}
	}

	mustHave := map[string]string{
		"--proxy-server=127.0.0.1:8080":          "route traffic through the capture proxy",
		"--ignore-certificate-errors-spki-list=": "trust the proxy MITM CA",
		"--user-data-dir=/tmp/profile":           "isolate from the user's main profile",
		"--proxy-bypass-list=<-loopback>":        "force loopback through the proxy",
		"https://example.com":                    "open the target",
	}
	for substr, why := range mustHave {
		if !strings.Contains(joined, substr) {
			t.Errorf("clean launch missing %q (needed to %s); got: %s", substr, why, joined)
		}
	}
}

// The helper's flag contract: a non-empty spkiHash adds
// --ignore-certificate-errors-spki-list; an empty hash omits it entirely.
func TestCleanBrowserArgsEmptySPKIOmitsFlag(t *testing.T) {
	withFlag := strings.Join(cleanBrowserArgs("127.0.0.1:8080", "HASH==", "/p", "https://x", false), " ")
	if !strings.Contains(withFlag, "--ignore-certificate-errors-spki-list=HASH==") {
		t.Errorf("non-empty spkiHash must add the flag; got: %s", withFlag)
	}
	noFlag := strings.Join(cleanBrowserArgs("127.0.0.1:8080", "", "/p", "https://x", false), " ")
	if strings.Contains(noFlag, "ignore-certificate-errors") {
		t.Errorf("empty spkiHash must omit the flag; got: %s", noFlag)
	}
}

func TestRendererCountNoProcess(t *testing.T) {
	// PID 1 (launchd/init) has no Chrome renderer children, so the count must
	// be zero — and the call must not error out on a pid it can't match.
	if n := rendererCount(1); n != 0 {
		t.Errorf("rendererCount(1) = %d, want 0", n)
	}
}

func TestCleanBrowserArgsHeadless(t *testing.T) {
	headful := strings.Join(cleanBrowserArgs("127.0.0.1:1", "h", "/p", "", false), " ")
	if strings.Contains(headful, "headless") {
		t.Errorf("headless=false must not add a headless flag; got: %s", headful)
	}
	headless := strings.Join(cleanBrowserArgs("127.0.0.1:1", "h", "/p", "", true), " ")
	if !strings.Contains(headless, "--headless=new") {
		t.Errorf("headless=true must add --headless=new; got: %s", headless)
	}
}

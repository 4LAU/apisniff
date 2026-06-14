package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

func NewBrowserContext(ctx context.Context, mode string, port int, userDataDir string, attachURL string, headless bool, extraOpts ...chromedp.ExecAllocatorOption) (context.Context, context.CancelFunc, error) {
	silentLog := chromedp.WithLogf(func(string, ...interface{}) {})
	switch mode {
	case "cdp-attach":
		if attachURL == "" {
			attachURL = fmt.Sprintf("http://127.0.0.1:%d", port)
		}
		allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, attachURL)
		browserCtx, browserCancel := chromedp.NewContext(allocCtx, silentLog)
		return browserCtx, func() {
			browserCancel()
			allocCancel()
		}, nil
	case "cdp-launch", "":
		tempProfile := false
		if userDataDir == "" {
			dir, err := os.MkdirTemp("", "apisniff-chrome-*")
			if err != nil {
				return nil, nil, err
			}
			userDataDir = dir
			tempProfile = true
		} else {
			if err := os.MkdirAll(userDataDir, 0o700); err != nil {
				return nil, nil, err
			}
		}
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(FindChrome()),
			chromedp.Flag("headless", headless),
			chromedp.Flag("remote-debugging-port", fmt.Sprintf("%d", port)),
			chromedp.UserDataDir(userDataDir),
			chromedp.NoFirstRun,
			chromedp.NoDefaultBrowserCheck,
		)
		opts = append(opts, extraOpts...)
		allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
		browserCtx, browserCancel := chromedp.NewContext(allocCtx, silentLog)
		return browserCtx, func() {
			browserCancel()
			allocCancel()
			if tempProfile {
				os.RemoveAll(userDataDir)
			}
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported recon mode %q", mode)
	}
}

// LaunchCleanBrowser starts a real Chrome routed through the given proxy and
// isolated in its own profile, with no automation flags and no DevTools port.
// This is the proxy-mode login path: nothing instruments the browser, so
// navigator.webdriver stays false and there is no CDP session for a bot vendor
// to detect — it is indistinguishable from a human's Chrome. The returned
// process is killed when ctx is cancelled (timeout or Ctrl+C).
func LaunchCleanBrowser(ctx context.Context, proxyAddr, spkiHash, profileDir, startURL string, headless bool) (*exec.Cmd, error) {
	chromePath, ok := ChromeAvailable()
	if !ok {
		return nil, fmt.Errorf("Chrome not found; install Chrome or Chromium, or rerun with --no-browser")
	}
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, chromePath, cleanBrowserArgs(proxyAddr, spkiHash, profileDir, startURL, headless)...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// cleanBrowserArgs builds the Chrome command line for the proxy-mode login
// path. It deliberately omits every automation signal: no --enable-automation,
// no --remote-debugging-port, no CDP. The --disable-* flags below only suppress
// Chrome's own phone-home (telemetry, component/variations updates,
// captive-portal probes) so they don't pollute the capture or stall the network
// service — none of them set navigator.webdriver.
//
// spkiHash is the trust path: when non-empty it adds
// --ignore-certificate-errors-spki-list so Chrome accepts the proxy MITM certs
// without any OS trust-store change. Chrome shows a cosmetic "unsupported flag"
// infobar (browser UI only, invisible to pages).
func cleanBrowserArgs(proxyAddr, spkiHash, profileDir, startURL string, headless bool) []string {
	args := []string{
		"--proxy-server=" + proxyAddr,
		"--proxy-bypass-list=<-loopback>",
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		"--disable-domain-reliability",
		"--disable-client-side-phishing-detection",
	}
	if spkiHash != "" {
		args = append(args, "--ignore-certificate-errors-spki-list="+spkiHash)
	}
	if headless {
		args = append(args, "--headless=new")
	}
	if startURL != "" {
		args = append(args, startURL)
	}
	return args
}

// watchAllPagesClosed signals when the launched Chrome has no open pages left —
// i.e. the user closed the last window or tab (⌘W) without quitting the app,
// which on macOS leaves the process running. It counts the browser's renderer
// child processes, scoped to its PID so a user's other Chrome instances are
// never considered. This is pure OS process inspection: no CDP, nothing visible
// to the page, so it preserves the clean-launch stealth.
//
// The returned channel closes once no renderers have been seen for a short
// debounce window — but only after at least one was seen, so it never fires
// during startup before the first page loads, and the debounce avoids a
// false end during the brief renderer swap of a cross-site navigation.
func watchAllPagesClosed(ctx context.Context, pid int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		sawPage := false
		zeros := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if rendererCount(pid) > 0 {
					sawPage = true
					zeros = 0
					continue
				}
				if !sawPage {
					continue
				}
				if zeros++; zeros >= 3 {
					return
				}
			}
		}
	}()
	return done
}

// rendererCount returns how many renderer child processes the browser at pid
// has. pgrep exits non-zero when nothing matches, which is a legitimate zero.
// Returns 0 on platforms without pgrep, so the caller simply relies on quit /
// Ctrl+C there.
func rendererCount(pid int) int {
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(pid), "-f", "type=renderer").Output()
	if err != nil {
		return 0
	}
	return len(strings.Fields(string(out)))
}

func FindChrome() string {
	candidates := []string{}
	switch runtime.GOOS {
	case "darwin":
		candidates = append(candidates,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		)
	case "linux":
		candidates = append(candidates, "google-chrome", "chromium", "chromium-browser")
	case "windows":
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			candidates = append(candidates, filepath.Join(local, "Google", "Chrome", "Application", "chrome.exe"))
		}
		if programFiles := os.Getenv("PROGRAMFILES"); programFiles != "" {
			candidates = append(candidates, filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"))
		}
	}
	for _, candidate := range candidates {
		if filepath.IsAbs(candidate) {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return "google-chrome"
}

func DefaultPort() int {
	return 9222 + int(time.Now().UnixNano()%1000)
}

func ChromeAvailable() (string, bool) {
	path := FindChrome()
	if path == "google-chrome" {
		// FindChrome returns this as fallback even when nothing is installed
		if _, err := exec.LookPath(path); err != nil {
			return "", false
		}
	}
	if filepath.IsAbs(path) {
		if _, err := os.Stat(path); err != nil {
			return "", false
		}
	}
	return path, true
}

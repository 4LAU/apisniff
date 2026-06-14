package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
// spkiHash is the fallback trust path: when non-empty it adds
// --ignore-certificate-errors-spki-list so Chrome accepts the proxy MITM certs.
// That flag triggers Chrome's "unsupported flag" warning bar, so the caller
// passes "" once the CA is trusted at the OS level (see EnsureCATrusted),
// yielding a warning-free, flag-free launch.
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

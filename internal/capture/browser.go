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

func NewBrowserContext(ctx context.Context, mode string, port int, userDataDir string, attachURL string, headless bool) (context.Context, context.CancelFunc, error) {
	switch mode {
	case "cdp-attach":
		if attachURL == "" {
			attachURL = fmt.Sprintf("http://127.0.0.1:%d", port)
		}
		allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, attachURL)
		browserCtx, browserCancel := chromedp.NewContext(allocCtx)
		return browserCtx, func() {
			browserCancel()
			allocCancel()
		}, nil
	case "cdp-launch", "":
		if userDataDir == "" {
			userDataDir = defaultUserDataDir()
		}
		if err := os.MkdirAll(userDataDir, 0o700); err != nil {
			return nil, nil, err
		}
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(FindChrome()),
			chromedp.Flag("headless", headless),
			chromedp.Flag("remote-debugging-port", fmt.Sprintf("%d", port)),
			chromedp.UserDataDir(userDataDir),
			chromedp.NoFirstRun,
			chromedp.NoDefaultBrowserCheck,
		)
		allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
		browserCtx, browserCancel := chromedp.NewContext(allocCtx)
		return browserCtx, func() {
			browserCancel()
			allocCancel()
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported recon mode %q", mode)
	}
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

func defaultUserDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "apisniff-chrome-profile")
	}
	return filepath.Join(home, ".apisniff", "chrome-profile")
}

func DefaultPort() int {
	return 9222 + int(time.Now().UnixNano()%1000)
}

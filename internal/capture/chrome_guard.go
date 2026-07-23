package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	chromeCloneRiskEnv       = "APISNIFF_ALLOW_CHROME_CLONE_RISK"
	chromeCloneGlob          = "/private/var/folders/*/*/X/com.google.Chrome.code_sign_clone"
	maxChromeCodeSignClones  = 3
	minChromeLaunchFreeBytes = 10 * 1024 * 1024 * 1024
)

func disableMacAppCodeSignClone() bool {
	return runtime.GOOS == "darwin"
}

func checkChromeLaunchSafety() error {
	if runtime.GOOS != "darwin" || envTruthy(os.Getenv(chromeCloneRiskEnv)) {
		return nil
	}
	if freeBytes, ok := freeDiskBytes(os.TempDir()); ok && freeBytes < minChromeLaunchFreeBytes {
		return fmt.Errorf("Chrome launch blocked: only %s free at %s. macOS Chrome code-sign clones can consume more than 1 GB per launch; free disk or set %s=1 to override", formatGiB(freeBytes), os.TempDir(), chromeCloneRiskEnv)
	}
	roots, err := filepath.Glob(chromeCloneGlob)
	if err != nil {
		return nil
	}
	total := 0
	for _, root := range roots {
		count, err := countChromeCodeSignClones(root)
		if err != nil {
			continue
		}
		total += count
	}
	if total > maxChromeCodeSignClones {
		return fmt.Errorf("Chrome launch blocked: found %d leftover Chrome code-sign clones under /private/var/folders. Delete the clones or set %s=1 to override", total, chromeCloneRiskEnv)
	}
	return nil
}

func countChromeCodeSignClones(root string) (int, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "code_sign_clone.") {
			count++
		}
	}
	return count, nil
}

func freeDiskBytes(path string) (uint64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, false
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), true
}

func envTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func formatGiB(bytes uint64) string {
	const gib = 1024 * 1024 * 1024
	if bytes < gib {
		return fmt.Sprintf("%d MiB", bytes/(1024*1024))
	}
	whole := bytes / gib
	frac := (bytes % gib) * 10 / gib
	return strconv.FormatUint(whole, 10) + "." + strconv.FormatUint(frac, 10) + " GiB"
}

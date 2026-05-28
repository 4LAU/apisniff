package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/4LAU/apisniff/internal/model"
)

func CapturesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "apisniff-captures")
	}
	return filepath.Join(home, "apisniff-captures")
}

func NewBundleDir(domain string, now time.Time) (string, error) {
	name := safeBundleName(domain) + "_" + now.UTC().Format("2006-01-02_15-04-05")
	path := filepath.Join(CapturesDir(), name)
	return path, os.MkdirAll(path, 0o700)
}

func WriteSession(path string, stats model.SessionStats) error {
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(path, "session.json"), data, 0o600)
}

func safeBundleName(domain string) string {
	replacer := strings.NewReplacer(".", "-", "/", "-", ":", ":")
	return replacer.Replace(domain)
}

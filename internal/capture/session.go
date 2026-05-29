package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/4LAU/apisniff/internal/bundle"
	"github.com/4LAU/apisniff/internal/model"
)

func NewBundleDir(domain string, now time.Time) (string, error) {
	name := bundle.SafeName(domain) + "_" + now.UTC().Format("2006-01-02_15-04-05")
	path := filepath.Join(bundle.Dir(), name)
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

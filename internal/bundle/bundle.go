package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const timestampLayout = "2006-01-02_15-04-05"

var bundleNameRe = regexp.MustCompile(`^(.+)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$`)

// Bundle is metadata for one capture bundle directory.
type Bundle struct {
	Path       string    `json:"path"`
	Name       string    `json:"name"`
	SafeName   string    `json:"safe_name"`
	Domain     string    `json:"domain,omitempty"`
	CapturedAt time.Time `json:"captured_at"`
	FlowCount  int       `json:"flow_count"`
	FileCount  int       `json:"file_count"`
	SizeBytes  int64     `json:"size_bytes"`
}

type sessionMetadata struct {
	Domain     string `json:"domain"`
	TotalFlows int    `json:"total_flows"`
	KeptFlows  int    `json:"kept_flows"`
}

// Dir returns the root directory that contains apisniff capture bundles.
func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "apisniff-captures")
	}
	return filepath.Join(home, "apisniff-captures")
}

// List returns metadata for valid capture bundle directories, newest first.
func List() ([]Bundle, error) {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	bundles := make([]Bundle, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		parsed, ok := parseName(entry.Name())
		if !ok {
			continue
		}
		meta, err := readBundle(filepath.Join(Dir(), entry.Name()), entry.Name(), parsed.safeName, parsed.createdAt)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, meta)
	}

	sortBundles(bundles)
	return bundles, nil
}

// Resolve accepts a direct bundle path or a domain/safe name and returns the newest matching bundle.
func Resolve(ref string) (Bundle, error) {
	if ref == "" {
		return Bundle{}, fmt.Errorf("bundle reference is required")
	}

	if bundle, ok, err := resolvePath(ref); err != nil || ok {
		return bundle, err
	}

	bundles, err := List()
	if err != nil {
		return Bundle{}, err
	}
	safeRef := SafeName(ref)
	for _, bundle := range bundles {
		if bundle.Domain == ref || bundle.SafeName == ref || bundle.SafeName == safeRef {
			return bundle, nil
		}
	}
	return Bundle{}, fmt.Errorf("no capture bundle found for %s", ref)
}

// Delete removes the bundle directory.
func Delete(bundle Bundle) error {
	if bundle.Path == "" {
		return fmt.Errorf("bundle path is required")
	}
	return os.RemoveAll(bundle.Path)
}

// CountOlderThan counts valid capture bundle directories older than threshold.
func CountOlderThan(threshold time.Duration) (int, error) {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}

	cutoff := time.Now().UTC().Add(-threshold)
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		parsed, ok := parseName(entry.Name())
		if !ok {
			continue
		}
		if parsed.createdAt.Before(cutoff) {
			count++
		}
	}
	return count, nil
}

// SafeName returns the filesystem-safe prefix used for bundle directories.
func SafeName(domain string) string {
	return strings.NewReplacer(".", "-", "/", "-", ":", "-").Replace(domain)
}

type parsedName struct {
	safeName  string
	createdAt time.Time
}

func parseName(name string) (parsedName, bool) {
	matches := bundleNameRe.FindStringSubmatch(name)
	if matches == nil {
		return parsedName{}, false
	}
	createdAt, err := time.Parse(timestampLayout, matches[2])
	if err != nil {
		return parsedName{}, false
	}
	return parsedName{safeName: matches[1], createdAt: createdAt}, true
}

func resolvePath(ref string) (Bundle, bool, error) {
	info, err := os.Stat(ref)
	if err == nil {
		if !info.IsDir() {
			return Bundle{}, true, fmt.Errorf("%s is not a bundle directory", ref)
		}
		return bundleFromPath(ref)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Bundle{}, true, err
	}

	if abs, err := filepath.Abs(ref); err == nil && abs != ref {
		info, statErr := os.Stat(abs)
		if statErr == nil {
			if !info.IsDir() {
				return Bundle{}, true, fmt.Errorf("%s is not a bundle directory", ref)
			}
			return bundleFromPath(abs)
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return Bundle{}, true, statErr
		}
	}
	return Bundle{}, false, nil
}

func bundleFromPath(path string) (Bundle, bool, error) {
	name := filepath.Base(filepath.Clean(path))
	parsed, ok := parseName(name)
	if !ok {
		if _, err := os.Stat(filepath.Join(path, "flows.jsonl")); err != nil {
			return Bundle{}, true, fmt.Errorf("%s is not a valid bundle directory name", path)
		}
		bundle, err := readBundle(path, name, name, time.Time{})
		return bundle, true, err
	}
	bundle, err := readBundle(path, name, parsed.safeName, parsed.createdAt)
	return bundle, true, err
}

func readBundle(path, name, safeName string, createdAt time.Time) (Bundle, error) {
	bundle := Bundle{
		Path:       path,
		Name:       name,
		SafeName:   safeName,
		CapturedAt: createdAt,
	}

	if session, ok := readSession(filepath.Join(path, "session.json")); ok {
		bundle.Domain = session.Domain
		if session.TotalFlows > 0 {
			bundle.FlowCount = session.TotalFlows
		} else {
			bundle.FlowCount = session.KeptFlows
		}
	}

	fileCount, sizeBytes, err := sizeMetadata(path)
	if err != nil {
		return Bundle{}, err
	}
	bundle.FileCount = fileCount
	bundle.SizeBytes = sizeBytes
	return bundle, nil
}

func readSession(path string) (sessionMetadata, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return sessionMetadata{}, false
	}
	var session sessionMetadata
	if err := json.Unmarshal(data, &session); err != nil {
		return sessionMetadata{}, false
	}
	return session, true
}

func sizeMetadata(root string) (int, int64, error) {
	var fileCount int
	var sizeBytes int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			fileCount++
			sizeBytes += info.Size()
		}
		return nil
	})
	return fileCount, sizeBytes, err
}

func sortBundles(bundles []Bundle) {
	sort.Slice(bundles, func(i, j int) bool {
		if bundles[i].CapturedAt.Equal(bundles[j].CapturedAt) {
			return bundles[i].Name > bundles[j].Name
		}
		return bundles[i].CapturedAt.After(bundles[j].CapturedAt)
	})
}

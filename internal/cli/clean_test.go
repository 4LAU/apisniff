package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/4LAU/apisniff/internal/bundle"
)

func TestCleanDryRunDoesNotDelete(t *testing.T) {
	restoreBundleStubs(t)
	bundleList = func() ([]bundle.Bundle, error) {
		return []bundle.Bundle{{Path: "/tmp/apisniff/example", Domain: "example.com"}}, nil
	}
	bundleDelete = func(bundle.Bundle) error {
		t.Fatal("dry-run should not delete")
		return nil
	}

	stdout, stderr, err := executeForTest(newCleanCommand(), "--all", "--dry-run", "--json")
	if err != nil {
		t.Fatalf("clean --dry-run returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var payload struct {
		DryRun  bool `json:"dry_run"`
		Deleted []struct {
			Path string `json:"path"`
		} `json:"deleted"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	if !payload.DryRun || len(payload.Deleted) != 1 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestCleanYesDeletes(t *testing.T) {
	restoreBundleStubs(t)
	first := bundle.Bundle{Path: "/tmp/apisniff/one", Domain: "example.com"}
	second := bundle.Bundle{Path: "/tmp/apisniff/two", Domain: "other.com"}
	bundleList = func() ([]bundle.Bundle, error) { return []bundle.Bundle{first, second}, nil }
	var deleted []string
	bundleDelete = func(ref bundle.Bundle) error {
		deleted = append(deleted, ref.Path)
		return nil
	}

	stdout, stderr, err := executeForTest(newCleanCommand(), "--domain", "example.com", "--yes", "--json")
	if err != nil {
		t.Fatalf("clean --yes returned error: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if strings.Join(deleted, ",") != first.Path {
		t.Fatalf("deleted = %#v", deleted)
	}
	var payload struct {
		Deleted []struct {
			Path string `json:"path"`
		} `json:"deleted"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout was not JSON: %v\n%s", err, stdout)
	}
	if len(payload.Deleted) != 1 {
		t.Fatalf("deleted = %d, want 1", len(payload.Deleted))
	}
}

func TestCleanNoFiltersErrors(t *testing.T) {
	restoreBundleStubs(t)
	stdout, _, err := executeForTest(newCleanCommand(), "--json")
	if err == nil {
		t.Fatal("clean without filters succeeded")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertContains(t, err.Error(), "requires at least one")
}

func TestCleanJSONWithoutYesOrDryRunErrorsNonInteractive(t *testing.T) {
	restoreBundleStubs(t)
	bundleList = func() ([]bundle.Bundle, error) {
		return []bundle.Bundle{{Path: "/tmp/apisniff/example", Domain: "example.com"}}, nil
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = read.Close()
		_ = write.Close()
	})
	cmd := newCleanCommand()
	cmd.SetIn(read)

	stdout, _, err := executeForTest(cmd, "--all", "--json")
	if err == nil {
		t.Fatal("clean --json without --yes or --dry-run succeeded")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertContains(t, err.Error(), "confirmation required")
}

func TestCleanZeroMatchesDoesNotRequireInteractiveConfirmation(t *testing.T) {
	restoreBundleStubs(t)
	bundleList = func() ([]bundle.Bundle, error) {
		return []bundle.Bundle{{Path: "/tmp/apisniff/example", Domain: "example.com"}}, nil
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = read.Close()
		_ = write.Close()
	})
	cmd := newCleanCommand()
	cmd.SetIn(read)

	_, stderr, err := executeForTest(cmd, "--domain", "missing.example")
	if err != nil {
		t.Fatalf("clean zero matches returned error: %v", err)
	}
	assertContains(t, stderr, "No bundles match")
}

func TestCleanOlderThanFilter(t *testing.T) {
	restoreBundleStubs(t)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	nowUTC = func() time.Time { return now }
	old := bundle.Bundle{Path: "/tmp/apisniff/old", CapturedAt: now.Add(-31 * 24 * time.Hour)}
	recent := bundle.Bundle{Path: "/tmp/apisniff/recent", CapturedAt: now.Add(-2 * time.Hour)}
	bundleList = func() ([]bundle.Bundle, error) { return []bundle.Bundle{old, recent}, nil }
	var deleted []string
	bundleDelete = func(ref bundle.Bundle) error {
		deleted = append(deleted, ref.Path)
		return nil
	}

	_, _, err := executeForTest(newCleanCommand(), "--older-than", "30d", "--yes", "--json")
	if err != nil {
		t.Fatalf("clean --older-than returned error: %v", err)
	}
	if strings.Join(deleted, ",") != old.Path {
		t.Fatalf("deleted = %#v", deleted)
	}
}

func TestCleanDomainFilterMatchesNormalizedSafeName(t *testing.T) {
	restoreBundleStubs(t)
	bundleList = func() ([]bundle.Bundle, error) {
		return []bundle.Bundle{{Path: "/tmp/apisniff/example", SafeName: "example-com"}}, nil
	}
	var deleted []string
	bundleDelete = func(ref bundle.Bundle) error {
		deleted = append(deleted, ref.Path)
		return nil
	}

	_, _, err := executeForTest(newCleanCommand(), "--domain", "example.com", "--yes", "--json")
	if err != nil {
		t.Fatalf("clean --domain returned error: %v", err)
	}
	if strings.Join(deleted, ",") != "/tmp/apisniff/example" {
		t.Fatalf("deleted = %#v", deleted)
	}
}

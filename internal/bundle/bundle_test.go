package bundle

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMissingCapturesDir(t *testing.T) {
	setHome(t)

	bundles, err := List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("List() len = %d, want 0", len(bundles))
	}

	count, err := CountOlderThan(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("CountOlderThan() error = %v", err)
	}
	if count != 0 {
		t.Fatalf("CountOlderThan() = %d, want 0", count)
	}
}

func TestListSkipsMalformedAndSortsNewestFirst(t *testing.T) {
	setHome(t)
	old := makeBundle(t, "api-v1_example-site_2026-05-27_01-02-03", `{"domain":"example.site","total_flows":3}`, "abc")
	newer := makeBundle(t, "api-v1_example-site_2026-05-28_01-02-03", `{"domain":"example.site","total_flows":5}`, "abcdef")
	makeBundle(t, "missing_timestamp", `{"domain":"bad.example","total_flows":9}`, "")
	makeBundle(t, "example_2026-05-28_01-02", `{"domain":"bad.example","total_flows":9}`, "")

	bundles, err := List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(bundles) != 2 {
		t.Fatalf("List() len = %d, want 2", len(bundles))
	}
	if bundles[0].Path != newer || bundles[1].Path != old {
		t.Fatalf("List() paths = %q, %q; want newest first", bundles[0].Path, bundles[1].Path)
	}
	if bundles[0].SafeName != "api-v1_example-site" {
		t.Fatalf("SafeName = %q, want regex prefix with underscores", bundles[0].SafeName)
	}
	if bundles[0].Domain != "example.site" || bundles[0].FlowCount != 5 {
		t.Fatalf("session metadata Domain=%q FlowCount=%d, want example.site/5", bundles[0].Domain, bundles[0].FlowCount)
	}
	if bundles[0].FileCount != 2 || bundles[0].SizeBytes != int64(len(`{"domain":"example.site","total_flows":5}`)+len("abcdef")) {
		t.Fatalf("size metadata FileCount=%d SizeBytes=%d", bundles[0].FileCount, bundles[0].SizeBytes)
	}
}

func TestListMissingOrCorruptSessionLeavesDomainEmpty(t *testing.T) {
	setHome(t)
	makeBundle(t, "missing-session_2026-05-28_01-02-03", "", "flow")
	makeBundle(t, "corrupt-session_2026-05-28_02-02-03", `{`, "flow")

	bundles, err := List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(bundles) != 2 {
		t.Fatalf("List() len = %d, want 2", len(bundles))
	}
	for _, got := range bundles {
		if got.Domain != "" {
			t.Fatalf("Domain = %q, want empty", got.Domain)
		}
		if got.SafeName == "" {
			t.Fatalf("SafeName is empty, want populated from directory name")
		}
		if got.FlowCount != 0 {
			t.Fatalf("FlowCount = %d, want 0 without valid session", got.FlowCount)
		}
	}
}

func TestResolveByDomainSafeNameAndPath(t *testing.T) {
	setHome(t)
	old := makeBundle(t, "example-com_2026-05-27_01-02-03", `{"domain":"example.com","total_flows":1}`, "")
	newer := makeBundle(t, "example-com_2026-05-28_01-02-03", `{"domain":"example.com","total_flows":2}`, "")
	_ = old

	byDomain, err := Resolve("example.com")
	if err != nil {
		t.Fatalf("Resolve(domain) error = %v", err)
	}
	if byDomain.Path != newer {
		t.Fatalf("Resolve(domain) Path = %q, want %q", byDomain.Path, newer)
	}

	bySafe, err := Resolve("example-com")
	if err != nil {
		t.Fatalf("Resolve(safe) error = %v", err)
	}
	if bySafe.Path != newer {
		t.Fatalf("Resolve(safe) Path = %q, want %q", bySafe.Path, newer)
	}

	byPath, err := Resolve(old)
	if err != nil {
		t.Fatalf("Resolve(path) error = %v", err)
	}
	if byPath.Path != old || byPath.FlowCount != 1 {
		t.Fatalf("Resolve(path) = %q/%d, want %q/1", byPath.Path, byPath.FlowCount, old)
	}
}

func TestDeleteRemovesDirectory(t *testing.T) {
	setHome(t)
	path := makeBundle(t, "delete-me_2026-05-28_01-02-03", `{"domain":"delete.me","total_flows":1}`, "")

	if err := Delete(Bundle{Path: path}); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Stat deleted path error = %v, want not exist", err)
	}
}

func TestCountOlderThanUsesNameTimestamps(t *testing.T) {
	setHome(t)
	old := time.Now().UTC().Add(-31 * 24 * time.Hour).Format(timestampLayout)
	recent := time.Now().UTC().Add(-2 * time.Hour).Format(timestampLayout)
	makeBundle(t, "old_"+old, `{"domain":"new.example","total_flows":1}`, "")
	makeBundle(t, "new_"+recent, `{"domain":"old.example","total_flows":1}`, "")
	makeBundle(t, "malformed", `{"domain":"old.example","total_flows":1}`, "")

	count, err := CountOlderThan(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("CountOlderThan() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("CountOlderThan() = %d, want 1", count)
	}
}

func TestResolveAllowsDirectUntimestampedBundleDir(t *testing.T) {
	setHome(t)
	path := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "session.json"), []byte(`{"domain":"example.com","total_flows":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "flows.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve(path) error = %v", err)
	}
	if got.Path != path || got.Domain != "example.com" || got.SafeName != "bundle" || got.FlowCount != 2 {
		t.Fatalf("Resolve(path) = %#v", got)
	}
}

func TestSafeNameReplacesPortColon(t *testing.T) {
	if got := SafeName("example.com:8443"); got != "example-com-8443" {
		t.Fatalf("SafeName() = %q, want example-com-8443", got)
	}
}

func setHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func makeBundle(t *testing.T, name, sessionJSON, flows string) string {
	t.Helper()
	path := filepath.Join(Dir(), name)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if sessionJSON != "" {
		if err := os.WriteFile(filepath.Join(path, "session.json"), []byte(sessionJSON), 0o600); err != nil {
			t.Fatalf("WriteFile(session) error = %v", err)
		}
	}
	if flows != "" {
		if err := os.WriteFile(filepath.Join(path, "flows.jsonl"), []byte(flows), 0o600); err != nil {
			t.Fatalf("WriteFile(flows) error = %v", err)
		}
	}
	return path
}

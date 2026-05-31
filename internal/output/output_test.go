package output

import (
	"bytes"
	"strings"
	"testing"
)

func testConfig(t *testing.T, buf *bytes.Buffer) Config {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	return Config{Color: false, Unicode: true, Width: 72, Writer: buf}
}

func TestStyleWidthClampAndTruncate(t *testing.T) {
	var buf bytes.Buffer
	s := newStyles(Config{Color: false, Unicode: true, Width: 500, Writer: &buf})
	if s.cfg.Width != 120 {
		t.Fatalf("width = %d, want 120", s.cfg.Width)
	}
	got := truncate("abcdefghijklmnopqrstuvwxyz", 10)
	if len(got) > 10 {
		t.Fatalf("truncated value length = %d, want <= 10: %q", len(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("truncated value = %q, want ellipsis", got)
	}
}

func TestWriteProbeRejectsNilAssessment(t *testing.T) {
	var buf bytes.Buffer
	err := WriteProbe(testConfig(t, &buf), nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "probe assessment is nil") {
		t.Fatalf("error = %v", err)
	}
	if buf.String() != "" {
		t.Fatalf("buffer = %q, want empty", buf.String())
	}
}

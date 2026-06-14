package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/4LAU/apisniff/internal/replay"
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

func TestWriteReplayShowsMergedRoutes(t *testing.T) {
	var buf bytes.Buffer
	summary := replay.Summary{
		Domain:  "example.com",
		Summary: map[string]int{"match": 1},
		Results: []replay.Result{{Method: "GET", Path: "/creditcards/{creditcardId}", Category: "match"}},
		Merges: []replay.DedupMerge{{
			Method: "GET",
			Key:    "/creditcards/{creditcardId}",
			Paths: []string{
				"/creditcards/cc_7w7CLKmd9I77HX2fjHfGPB",
				"/creditcards/cc_9BMqukMwYVs6SY1psJlh0f",
			},
		}},
	}
	if err := WriteReplay(testConfig(t, &buf), summary); err != nil {
		t.Fatalf("WriteReplay: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Merged routes") {
		t.Fatalf("output missing Merged routes section:\n%s", out)
	}
	if !strings.Contains(out, "GET /creditcards/{creditcardId}") || !strings.Contains(out, "2 paths merged") {
		t.Fatalf("output missing merge detail:\n%s", out)
	}
}

func TestWriteReplayNoMergeSectionWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	summary := replay.Summary{
		Domain:  "example.com",
		Summary: map[string]int{"match": 1},
		Results: []replay.Result{{Method: "GET", Path: "/health", Category: "match"}},
	}
	if err := WriteReplay(testConfig(t, &buf), summary); err != nil {
		t.Fatalf("WriteReplay: %v", err)
	}
	if strings.Contains(buf.String(), "Merged routes") {
		t.Fatalf("unexpected Merged routes section with no merges:\n%s", buf.String())
	}
}

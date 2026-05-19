package replay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCookieFileAndMatchHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.txt")
	data := "# Netscape HTTP Cookie File\n" +
		".example.com\tTRUE\t/\tTRUE\t2147483647\tsid\tabc\n" +
		"api.example.com\tFALSE\t/\tTRUE\t2147483647\tapi\tdef\n" +
		"other.example.com\tFALSE\t/\tTRUE\t2147483647\tother\tghi\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	cookies, err := ParseCookieFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got := CookiesForHost(cookies, "api.example.com")
	if got != "sid=abc; api=def" {
		t.Fatalf("cookie header = %q", got)
	}
	if got := CookiesForHost(cookies, "example.com"); got != "sid=abc" {
		t.Fatalf("apex cookie header = %q", got)
	}
	if got := CookiesForHost(cookies, "evil-example.com"); got != "" {
		t.Fatalf("unexpected suffix cookie header = %q", got)
	}
}

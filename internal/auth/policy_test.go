package auth

import "testing"

func TestIsCredentialQueryParamRecall(t *testing.T) {
	credentials := []string{
		"api_key", "apikey", "key", "API_KEY",
		"access_token", "refresh_token", "id_token", "auth_token", "token",
		"client_secret", "secret", "password", "passwd", "pwd",
		"signature", "sig", "session", "session_id", "sid", "jwt", "bearer", "auth",
	}
	for _, name := range credentials {
		if !IsCredentialQueryParam(name) {
			t.Errorf("IsCredentialQueryParam(%q) = false, want true", name)
		}
	}
	benign := []string{"q", "page", "limit", "monkey", "keyboard", "author", "authorize", "sort", "ids"}
	for _, name := range benign {
		if IsCredentialQueryParam(name) {
			t.Errorf("IsCredentialQueryParam(%q) = true, want false", name)
		}
	}
}

func TestStripCredentialQueryParamsPreservesRestOfURL(t *testing.T) {
	got := StripCredentialQueryParams("https://api.example.com/v1/items?page=2&api_key=sk&q=a%20b&access_token=t")
	want := "https://api.example.com/v1/items?page=2&q=a%20b"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := StripCredentialQueryParams("https://api.example.com/v1/items"); got != "https://api.example.com/v1/items" {
		t.Fatalf("query-less URL changed: %q", got)
	}
}

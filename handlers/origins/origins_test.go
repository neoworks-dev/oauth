package origins

import (
	"slices"
	"testing"
)

func TestFromRedirectURIsDedupesOrigins(t *testing.T) {
	got := FromRedirectURIs([]string{
		"https://app.example/auth/callback",
		"https://app.example/other",    // same origin
		"https://admin.app.example/cb", // different host
		"http://localhost:3000/cb",     // scheme + port
		"not a url",                    // skipped
	})
	want := []string{
		"https://app.example",
		"https://admin.app.example",
		"http://localhost:3000",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAllows(t *testing.T) {
	uris := []string{"https://app.example/cb", "http://localhost:3000/cb"}

	if !Allows(uris, "https://app.example") {
		t.Error("registered origin should be allowed")
	}
	if !Allows(uris, "http://localhost:3000") {
		t.Error("registered origin with port should be allowed")
	}
	if Allows(uris, "https://evil.example") {
		t.Error("unregistered origin must be denied")
	}
	if Allows(uris, "") {
		t.Error("empty origin must be denied")
	}
}

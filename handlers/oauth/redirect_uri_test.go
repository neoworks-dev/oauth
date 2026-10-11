package oauth

import "testing"

func TestRedirectURIRegistered(t *testing.T) {
	registered := []string{
		"https://app.example.com/callback",
		"http://127.0.0.1/callback",
		"http://[::1]:8080/callback?app=desktop",
		"http://localhost:5173/callback",
	}
	cases := map[string]struct {
		requested string
		want      bool
	}{
		"exact https":                         {"https://app.example.com/callback", true},
		"https on another port":               {"https://app.example.com:8443/callback", false},
		"ipv4 loopback on a runtime port":     {"http://127.0.0.1:49152/callback", true},
		"ipv4 loopback without a port":        {"http://127.0.0.1/callback", true},
		"ipv6 loopback on another port":       {"http://[::1]:49152/callback?app=desktop", true},
		"loopback with another path":          {"http://127.0.0.1:49152/other", false},
		"loopback with another query":         {"http://[::1]:49152/callback?app=web", false},
		"loopback with a trailing slash":      {"http://127.0.0.1:49152/callback/", false},
		"loopback over https":                 {"https://127.0.0.1:49152/callback", false},
		"loopback with credentials":           {"http://user@127.0.0.1:49152/callback", false},
		"loopback with a fragment":            {"http://127.0.0.1:49152/callback#x", false},
		"other loopback address":              {"http://127.0.0.2:49152/callback", false},
		"localhost on another port":           {"http://localhost:5174/callback", false},
		"localhost on its registered port":    {"http://localhost:5173/callback", true},
		"ipv4 loopback for the ipv6 redirect": {"http://127.0.0.1:8080/callback?app=desktop", false},
	}
	for name, testCase := range cases {
		got := redirectURIRegistered(registered, testCase.requested)
		if got != testCase.want {
			t.Errorf("%s: redirectURIRegistered(%q) = %v, want %v", name, testCase.requested, got, testCase.want)
		}
	}
}

package flowtest

import (
	"testing"

	"github.com/neoworks/oauth/internal/testsupport"
)

// A native app registers its loopback redirect without a port and asks for the
// callback on whatever port it listens on.
func TestAuthorizeMatchesLoopbackRedirectsOnAnyPort(t *testing.T) {
	system := newSystem(t)
	clientID := "native-" + testsupport.NewAccount("x@example.com").UserID[:8]
	if err := testSurreal.CreateClient(clientID, []string{"http://127.0.0.1/callback"}, allScopes(), false); err != nil {
		t.Fatal(err)
	}
	_, challenge := pkce()
	cases := map[string]struct {
		redirectURI string
		wantPrefix  string
	}{
		"runtime port":  {"http://127.0.0.1:49152/callback", vaultOrigin + "/signin"},
		"other path":    {"http://127.0.0.1:49152/other", "/oauth/error"},
		"localhost":     {"http://localhost:49152/callback", "/oauth/error"},
		"other address": {"http://127.0.0.2:49152/callback", "/oauth/error"},
	}
	for name, testCase := range cases {
		params := system.authorizeParams(testsupport.NewInstall(), challenge, "openid @neoworks/calendar:read")
		params.Set("client_id", clientID)
		params.Set("redirect_uri", testCase.redirectURI)
		location := system.authorize(params)
		if !hasPrefix(location.String(), testCase.wantPrefix) {
			t.Errorf("%s: authorize redirected to %s, want %s", name, location, testCase.wantPrefix)
		}
	}
}

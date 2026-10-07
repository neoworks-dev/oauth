package flowtest

import (
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/neoworks/oauth/internal/testsupport"
)

func TestConcurrentRefreshConvergesOnOneRotatedToken(t *testing.T) {
	system := newSystem(t)
	issued := system.issueTokens(system.freshAccount("race"))
	original := issued.Body["refresh_token"].(string)

	const callers = 12
	results := make([]testsupport.Response, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			results[slot] = system.refresh(original)
		}(index)
	}
	group.Wait()

	rotated := map[string]bool{}
	for _, result := range results {
		if result.Status != 200 {
			t.Fatalf("every concurrent caller must get a usable result, got %d %s", result.Status, result.Raw)
		}
		rotated[result.Body["refresh_token"].(string)] = true
	}
	if len(rotated) != 1 {
		t.Fatalf("callers must converge on a single rotated token, got %d", len(rotated))
	}
}

func TestReusingARotatedTokenAfterTheGraceWindowRevokesTheFamily(t *testing.T) {
	system := newSystem(t)
	issued := system.issueTokens(system.freshAccount("replay"))
	original := issued.Body["refresh_token"].(string)
	rotated := system.refresh(original)
	if rotated.Status != 200 {
		t.Fatalf("first refresh: %d %s", rotated.Status, rotated.Raw)
	}

	system.redis.FastForward(2 * time.Minute)
	if replay := system.refresh(original); replay.Status != 400 {
		t.Fatalf("a replayed token must be refused, got %d", replay.Status)
	}
	if successor := system.refresh(rotated.Body["refresh_token"].(string)); successor.Status != 400 {
		t.Fatalf("the replay must revoke the family, got %d", successor.Status)
	}
}

func TestTokenEndpointRejectsHostileInput(t *testing.T) {
	system := newSystem(t)
	cases := map[string]map[string]string{
		"unknown grant":      {"grant_type": "password", "username": "a", "password": "b"},
		"client credentials": {"grant_type": "client_credentials", "client_id": system.clientID},
		"empty":              {},
		"no code":            {"grant_type": "authorization_code", "redirect_uri": appRedirect},
		"unknown code":       {"grant_type": "authorization_code", "code": "nope", "redirect_uri": appRedirect, "code_verifier": "x"},
		"unknown refresh":    {"grant_type": "refresh_token", "refresh_token": "nope"},
	}
	for name, form := range cases {
		t.Run(name, func(t *testing.T) {
			response := testsupport.Form(system.oauth, "/oauth/token", form, nil)
			if response.Status != 400 {
				t.Fatalf("status %d (%s), want 400", response.Status, response.Raw)
			}
			if response.Body["error"] == nil {
				t.Fatalf("expected an OAuth error body, got %s", response.Raw)
			}
		})
	}
}

func TestAnAuthorizationCodeCannotBeRedeemedWithAnotherRedirectURI(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("redirect")
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/photos:read"))
	body := consentFor(account, install, system.clientID, challengeID(location), []string{"@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})
	consent := system.browser.Do("POST", "/vault/consent", body, nil)
	redirect := consent.Body["redirect"].(string)
	response := testsupport.Form(system.oauth, "/oauth/token", map[string]string{
		"grant_type": "authorization_code", "code": extractCode(redirect), "redirect_uri": "http://other.test/callback",
		"client_id": system.clientID, "code_verifier": verifier,
	}, nil)
	if response.Status != 400 {
		t.Fatalf("status %d, want 400", response.Status)
	}
}

func extractCode(redirect string) string {
	parsed, _ := url.Parse(redirect)
	return parsed.Query().Get("code")
}

func TestAnExpiredAuthorizationCodeIsRefused(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("expired")
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/photos:read"))
	body := consentFor(account, install, system.clientID, challengeID(location), []string{"@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})
	consent := system.browser.Do("POST", "/vault/consent", body, nil)

	system.redis.FastForward(10 * time.Minute)
	response := system.exchange(extractCode(consent.Body["redirect"].(string)), verifier)
	if response.Status != 400 || response.Body["error"] != "invalid_grant" {
		t.Fatalf("expired code: %d %s", response.Status, response.Raw)
	}
}

func TestAuthorizeErrorsKeepTheStateAndUnknownClientsGetTheErrorPage(t *testing.T) {
	system := newSystem(t)
	_, challenge := pkce()
	params := system.authorizeParams(testsupport.NewInstall(), challenge, "openid")
	params.Set("response_type", "token")
	location := system.authorize(params)
	if location.Query().Get("error") != "unsupported_response_type" || location.Query().Get("state") != "state-1" {
		t.Fatalf("unexpected redirect %s", location)
	}

	params = system.authorizeParams(testsupport.NewInstall(), challenge, "openid")
	params.Set("client_id", "nobody")
	location = system.authorize(params)
	if location.Path != "/oauth/error" || location.Query().Get("error") != "unauthorized_client" {
		t.Fatalf("an unknown client must get the local error page, got %s", location)
	}
}

func TestAccessTokensVerifyAgainstThePublishedKeySet(t *testing.T) {
	system := newSystem(t)
	issued := system.issueTokens(system.freshAccount("jwks"))
	accessToken := issued.Body["access_token"].(string)

	keySet := system.getJSON("/.well-known/jwks.json")
	keys := keySet["keys"].([]any)
	key := keys[0].(map[string]any)
	if key["alg"] != "ES256" || key["kty"] != "EC" || key["crv"] != "P-256" {
		t.Fatalf("unexpected key %v", key)
	}
	claims, err := verifyWithJWK(accessToken, key)
	if err != nil {
		t.Fatalf("token does not verify against the JWKS: %v", err)
	}
	if claims["client_id"] != system.clientID || claims["install_id"] == nil || claims["iss"] != "http://oauth.test" {
		t.Fatalf("unexpected claims %v", claims)
	}
}

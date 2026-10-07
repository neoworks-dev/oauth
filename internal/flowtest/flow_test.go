package flowtest

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/wire"
)

// consentFor builds the body a vault posts to approve an install on the roots
// of the given collections, carrying the roots the account has none of yet.
func consentFor(account *testsupport.Account, install testsupport.Install, clientID, challengeID string, grantScopes []string, roles map[string]string) map[string]any {
	certificate := account.Certificate(testsupport.CertificateParams{
		InstallID: install.ID, ClientID: clientID,
		InstallEncPub: wire.EncodeBase64URL(install.EncPub[:]), InstallSignPub: wire.EncodeBase64URL(install.SignPub),
		Scopes: grantScopes, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})
	collections := []string{}
	for collection := range roles {
		collections = append(collections, collection)
	}
	roots := account.NewRoots(collections, storedRoots(account))
	grants := []map[string]any{}
	for collection, role := range roles {
		grants = append(grants, account.Grant(account.RootIDs[collection], "install", install.ID, role, 1, nil, install.EncPub, certificate.CertID))
	}
	return map[string]any{
		"loginChallenge": challengeID, "scopes": grantScopes,
		"certificate": certificate.Bytes, "certificateSignature": certificate.Signature, "grants": grants,
		"roots": roots,
	}
}

// storedRoots lists the collections the server holds the account's roots in.
func storedRoots(account *testsupport.Account) []string {
	collections, err := testSurreal.Store.RootCollections(context.Background(), account.UserID)
	if err != nil {
		panic(err)
	}
	return collections
}

func challengeID(location *url.URL) string {
	return location.Query().Get("login_challenge")
}

func TestAuthorizationCodeFlowBindsTokensToTheInstall(t *testing.T) {
	system := newSystem(t)
	account := testsupport.NewAccount("flow-" + testsupport.NewAccount("x@example.com").UserID[:8] + "@example.com")
	system.signUp(account)
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	scope := "openid @neoworks/calendar:read @neoworks/calendar:write @neoworks/contacts:read"

	location := system.authorize(system.authorizeParams(install, challenge, scope))
	if !hasPrefix(location.String(), vaultOrigin+"/signin") {
		t.Fatalf("authorize must hand over to the vault, got %s", location)
	}
	view := system.browser.Do("GET", "/vault/challenge?login_challenge="+challengeID(location), nil, nil)
	installView, _ := view.Body["install"].(map[string]any)
	if view.Status != 200 || installView["id"] != install.ID {
		t.Fatalf("challenge view: %d %s", view.Status, view.Raw)
	}

	grantScopes := []string{"openid", "@neoworks/calendar:read", "@neoworks/calendar:write", "@neoworks/contacts:read"}
	body := consentFor(account, install, system.clientID, challengeID(location), grantScopes, map[string]string{"@neoworks/calendar": "write", "@neoworks/contacts": "read"})
	consent := system.browser.Do("POST", "/vault/consent", body, nil)
	if consent.Status != 200 {
		t.Fatalf("consent: %d %s", consent.Status, consent.Raw)
	}
	redirect, _ := url.Parse(consent.Body["redirect"].(string))
	if redirect.Query().Get("state") != "state-1" || redirect.Query().Get("code") == "" {
		t.Fatalf("unexpected redirect %s", redirect)
	}

	tokenResponse := system.exchange(redirect.Query().Get("code"), verifier)
	if tokenResponse.Status != 200 {
		t.Fatalf("token: %d %s", tokenResponse.Status, tokenResponse.Raw)
	}
	assertGrantPayload(t, tokenResponse.Body, install.ID, 2)

	accessToken := tokenResponse.Body["access_token"].(string)
	introspection := system.introspect(accessToken, accessToken)
	if introspection.Body["active"] != true || introspection.Body["install_id"] != install.ID || introspection.Body["sub"] != account.UserID {
		t.Fatalf("introspection %s", introspection.Raw)
	}

	replay := system.exchange(redirect.Query().Get("code"), verifier)
	if replay.Status != 400 {
		t.Fatalf("an authorization code must work once, got %d", replay.Status)
	}
}

func assertGrantPayload(t *testing.T, body map[string]any, installID string, wantGrants int) {
	t.Helper()
	grant, ok := body["neoworks_grant"].(map[string]any)
	if !ok {
		t.Fatalf("token response lacks neoworks_grant: %v", body)
	}
	grants, _ := grant["grants"].([]any)
	if grant["installId"] != installID || grant["certificate"] == "" || grant["certificateSignature"] == "" || len(grants) != wantGrants {
		t.Fatalf("unexpected neoworks_grant %v", grant)
	}
	first, _ := grants[0].(map[string]any)
	if first["principalType"] != "install" || first["principalId"] != installID || first["wrappedKeys"] == "" {
		t.Fatalf("unexpected grant %v", first)
	}
}

func TestAuthorizeRequiresPKCEAndInstallForDataScopes(t *testing.T) {
	system := newSystem(t)
	install := testsupport.NewInstall()
	_, challenge := pkce()

	cases := map[string]func(params url.Values){
		"no challenge": func(params url.Values) { params.Del("code_challenge") },
		"plain method": func(params url.Values) { params.Set("code_challenge_method", "plain") },
		"no install": func(params url.Values) {
			params.Del("install_id")
			params.Del("install_enc_pub")
			params.Del("install_sign_pub")
		},
		"partial install":  func(params url.Values) { params.Del("install_sign_pub") },
		"bad install key":  func(params url.Values) { params.Set("install_enc_pub", "AAAA") },
		"unknown scope":    func(params url.Values) { params.Set("scope", "@neoworks/calendar:admin") },
		"non uuid install": func(params url.Values) { params.Set("install_id", "install-1") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			params := system.authorizeParams(install, challenge, "@neoworks/calendar:read")
			mutate(params)
			location := system.authorize(params)
			if location.Query().Get("error") != "invalid_request" && location.Query().Get("error") != "invalid_scope" {
				t.Fatalf("expected an error redirect, got %s", location)
			}
			if !hasPrefix(location.String(), appRedirect) {
				t.Fatalf("errors go back to the registered redirect URI, got %s", location)
			}
		})
	}
}

func TestTokenExchangeChecksPKCE(t *testing.T) {
	system := newSystem(t)
	account := testsupport.NewAccount("pkce-" + testsupport.NewAccount("x@example.com").UserID[:8] + "@example.com")
	system.signUp(account)
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/contacts:read"))
	body := consentFor(account, install, system.clientID, challengeID(location), []string{"@neoworks/contacts:read"}, map[string]string{"@neoworks/contacts": "read"})
	consent := system.browser.Do("POST", "/vault/consent", body, nil)
	redirect, _ := url.Parse(consent.Body["redirect"].(string))
	code := redirect.Query().Get("code")

	if wrong := system.exchange(code, "not-the-verifier"); wrong.Status != 400 {
		t.Fatalf("wrong verifier: status %d", wrong.Status)
	}
	if again := system.exchange(code, verifier); again.Status != 400 {
		t.Fatalf("the code is consumed by the failed attempt, got %d", again.Status)
	}
}

func TestConsentRejectsBadCertificatesAndGrants(t *testing.T) {
	system := newSystem(t)
	account := testsupport.NewAccount("consent-" + testsupport.NewAccount("x@example.com").UserID[:8] + "@example.com")
	system.signUp(account)
	stranger := testsupport.NewAccount("stranger@example.com")
	install := testsupport.NewInstall()
	_, challenge := pkce()
	scopes := []string{"@neoworks/calendar:read"}

	cases := map[string]func(body map[string]any){
		"certificate signed by another key": func(body map[string]any) {
			forged := stranger.Certificate(testsupport.CertificateParams{
				InstallID: install.ID, ClientID: system.clientID, InstallEncPub: wire.EncodeBase64URL(install.EncPub[:]),
				InstallSignPub: wire.EncodeBase64URL(install.SignPub), Scopes: scopes, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			})
			body["certificate"], body["certificateSignature"] = forged.Bytes, forged.Signature
		},
		"role above the scope": func(body map[string]any) {
			cert := account.Certificate(testsupport.CertificateParams{
				InstallID: install.ID, ClientID: system.clientID, InstallEncPub: wire.EncodeBase64URL(install.EncPub[:]),
				InstallSignPub: wire.EncodeBase64URL(install.SignPub), Scopes: scopes, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			})
			body["certificate"], body["certificateSignature"] = cert.Bytes, cert.Signature
			body["grants"] = []map[string]any{account.Grant(account.RootIDs["@neoworks/calendar"], "install", install.ID, "write", 1, nil, install.EncPub, cert.CertID)}
		},
		"admin role": func(body map[string]any) {
			cert := account.Certificate(testsupport.CertificateParams{
				InstallID: install.ID, ClientID: system.clientID, InstallEncPub: wire.EncodeBase64URL(install.EncPub[:]),
				InstallSignPub: wire.EncodeBase64URL(install.SignPub), Scopes: scopes, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			})
			body["certificate"], body["certificateSignature"] = cert.Bytes, cert.Signature
			body["grants"] = []map[string]any{account.Grant(account.RootIDs["@neoworks/calendar"], "install", install.ID, "admin", 1, nil, install.EncPub, cert.CertID)}
		},
		"node of another user": func(body map[string]any) {
			body["grants"] = []map[string]any{stranger.Grant(stranger.RootIDs["@neoworks/calendar"], "install", install.ID, "read", 1, nil, install.EncPub, "")}
		},
		"grant to another install": func(body map[string]any) {
			other := testsupport.NewInstall()
			cert := body["certificate"].(string)
			_ = cert
			body["grants"] = []map[string]any{account.Grant(account.RootIDs["@neoworks/calendar"], "install", other.ID, "read", 1, nil, other.EncPub, "")}
		},
		"no grants": func(body map[string]any) {
			body["grants"] = []map[string]any{}
		},
		"expired certificate": func(body map[string]any) {
			cert := account.Certificate(testsupport.CertificateParams{
				InstallID: install.ID, ClientID: system.clientID, InstallEncPub: wire.EncodeBase64URL(install.EncPub[:]),
				InstallSignPub: wire.EncodeBase64URL(install.SignPub), Scopes: scopes, IssuedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
			})
			body["certificate"], body["certificateSignature"] = cert.Bytes, cert.Signature
		},
		"scope not requested": func(body map[string]any) {
			body["scopes"] = []string{"@neoworks/calendar:read", "@neoworks/files:read"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/calendar:read"))
			body := consentFor(account, install, system.clientID, challengeID(location), scopes, map[string]string{"@neoworks/calendar": "read"})
			mutate(body)
			response := system.browser.Do("POST", "/vault/consent", body, nil)
			if response.Status != 400 {
				t.Fatalf("status %d (%s), want 400", response.Status, response.Raw)
			}
		})
	}
}

func TestRevokedInstallLosesRefreshAndIntrospection(t *testing.T) {
	system := newSystem(t)
	account := testsupport.NewAccount("revoke-" + testsupport.NewAccount("x@example.com").UserID[:8] + "@example.com")
	system.signUp(account)
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/photos:read"))
	body := consentFor(account, install, system.clientID, challengeID(location), []string{"@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})
	consent := system.browser.Do("POST", "/vault/consent", body, nil)
	redirect, _ := url.Parse(consent.Body["redirect"].(string))
	issued := system.exchange(redirect.Query().Get("code"), verifier)
	accessToken := issued.Body["access_token"].(string)

	refreshed := system.refresh(issued.Body["refresh_token"].(string))
	if refreshed.Status != 200 || refreshed.Body["refresh_token"] == issued.Body["refresh_token"] {
		t.Fatalf("refresh must rotate the token: %d %s", refreshed.Status, refreshed.Raw)
	}
	if err := testSurreal.Exec("UPDATE $id SET revoked_at = time::now()", map[string]any{"id": installRecord(install.ID)}); err != nil {
		t.Fatal(err)
	}
	if blocked := system.refresh(refreshed.Body["refresh_token"].(string)); blocked.Status != 400 {
		t.Fatalf("refresh after revoking the install: status %d", blocked.Status)
	}
	inactive := system.introspect(accessToken, accessToken)
	if inactive.Body["active"] != false {
		t.Fatalf("a token of a revoked install must be inactive: %s", inactive.Raw)
	}
}

func TestIdentityOnlyAuthorizationNeedsNoInstall(t *testing.T) {
	system := newSystem(t)
	account := testsupport.NewAccount("identity-" + testsupport.NewAccount("x@example.com").UserID[:8] + "@example.com")
	system.signUp(account)
	verifier, challenge := pkce()
	params := system.authorizeParams(testsupport.NewInstall(), challenge, "openid email")
	params.Del("install_id")
	params.Del("install_enc_pub")
	params.Del("install_sign_pub")
	location := system.authorize(params)
	consent := system.browser.Do("POST", "/vault/consent", map[string]any{"loginChallenge": challengeID(location), "scopes": []string{"openid", "email"}}, nil)
	if consent.Status != 200 {
		t.Fatalf("consent: %d %s", consent.Status, consent.Raw)
	}
	redirect, _ := url.Parse(consent.Body["redirect"].(string))
	issued := system.exchange(redirect.Query().Get("code"), verifier)
	if issued.Status != 200 || issued.Body["neoworks_grant"] != nil {
		t.Fatalf("token: %d %s", issued.Status, issued.Raw)
	}
}

func TestIdentityScopesWithInstallParametersIssueAnInstalllessToken(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("identityinstall")
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "openid email"))
	consent := system.browser.Do("POST", "/vault/consent", map[string]any{"loginChallenge": challengeID(location), "scopes": []string{"openid", "email"}}, nil)
	if consent.Status != 200 {
		t.Fatalf("consent without a certificate: %d %s", consent.Status, consent.Raw)
	}
	redirect, _ := url.Parse(consent.Body["redirect"].(string))
	issued := system.exchange(redirect.Query().Get("code"), verifier)
	accessToken := issued.Body["access_token"].(string)
	introspection := system.introspect(accessToken, accessToken)
	if issued.Body["neoworks_grant"] != nil || introspection.Body["install_id"] != nil || introspection.Body["sub"] != account.UserID {
		t.Fatalf("identity-only tokens carry no install: %s / %s", issued.Raw, introspection.Raw)
	}
}

func TestConsentCreatesOnlyNewEmptyRootsOfApprovedCollections(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("roots")
	install := testsupport.NewInstall()
	_, challenge := pkce()
	scopes := []string{"@neoworks/calendar:read"}

	cases := map[string]func(body map[string]any){
		"root of a collection not approved": func(body map[string]any) {
			extra := account.NewRoots([]string{"@neoworks/files"}, nil)
			body["roots"] = append(body["roots"].([]map[string]any), extra...)
		},
		"root with content": func(body map[string]any) {
			root := body["roots"].([]map[string]any)[0]["node"].(map[string]any)
			root["content"] = "CgNhYmM"
		},
		"owner grant sealed over other keys": func(body map[string]any) {
			grant := body["roots"].([]map[string]any)[0]["grant"].(map[string]any)
			grant["wrappedKeys"] = wire.EncodeBase64URL(testsupport.Seal(account.EncPub, make([]byte, 32)))
		},
		"owner grant for another principal": func(body map[string]any) {
			grant := body["roots"].([]map[string]any)[0]["grant"].(map[string]any)
			grant["principalId"] = testsupport.NewAccount("other@example.com").UserID
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/calendar:read"))
			body := consentFor(account, install, system.clientID, challengeID(location), scopes, map[string]string{"@neoworks/calendar": "read"})
			mutate(body)
			response := system.browser.Do("POST", "/vault/consent", body, nil)
			if response.Status != 400 || response.Body["error"] != "invalid_roots" {
				t.Fatalf("status %d (%s), want 400 invalid_roots", response.Status, response.Raw)
			}
		})
	}

	location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/calendar:read"))
	body := consentFor(account, install, system.clientID, challengeID(location), scopes, map[string]string{"@neoworks/calendar": "read"})
	if response := system.browser.Do("POST", "/vault/consent", body, nil); response.Status != 200 {
		t.Fatalf("the first consent should create the calendar root: %d %s", response.Status, response.Raw)
	}
	account.CommitGrants()
	tree := system.browser.Do("GET", "/vault/tree", nil, nil)
	schemas, _ := tree.Body["schemas"].(map[string]any)
	if len(tree.Body["nodes"].([]any)) != 1 || schemas["@neoworks/calendar"] == nil {
		t.Fatalf("the tree should hold the new root and its collection's schema: %s", tree.Raw)
	}

	again := testsupport.NewInstall()
	location = system.authorize(system.authorizeParams(again, challenge, "@neoworks/calendar:read"))
	second := consentFor(account, again, system.clientID, challengeID(location), scopes, map[string]string{"@neoworks/calendar": "read"})
	second["roots"] = []map[string]any{{"node": body["roots"].([]map[string]any)[0]["node"], "grant": body["roots"].([]map[string]any)[0]["grant"]}}
	if response := system.browser.Do("POST", "/vault/consent", second, nil); response.Body["error"] != "invalid_roots" {
		t.Fatalf("a second root in a collection: %d %s, want invalid_roots", response.Status, response.Raw)
	}
}

func TestAuthorizeRefusesCollectionsThatAreNotPublishedNodeSchemas(t *testing.T) {
	system := newSystem(t)
	install := testsupport.NewInstall()
	_, challenge := pkce()
	if err := testSurreal.CreateClient("unpublished-"+install.ID[:8], []string{appRedirect}, []string{"@nobody/unpublished:read"}, false); err != nil {
		t.Fatal(err)
	}
	params := system.authorizeParams(install, challenge, "@nobody/unpublished:read")
	params.Set("client_id", "unpublished-"+install.ID[:8])
	location := system.authorize(params)
	if location.Query().Get("error") != "invalid_scope" {
		t.Fatalf("expected invalid_scope, got %s", location)
	}
}

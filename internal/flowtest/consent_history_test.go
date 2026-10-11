package flowtest

import (
	"net/url"
	"slices"
	"testing"

	"github.com/neoworks/oauth/internal/testsupport"
)

// approve authorizes the install for the scopes with a read grant on each collection.
func (system *system) approve(account *testsupport.Account, install testsupport.Install, scopes []string, roles map[string]string) {
	system.t.Helper()
	_, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, joinScopes(scopes)))
	body := consentFor(account, install, system.clientID, challengeID(location), scopes, roles)
	consent := system.browser.Do("POST", "/vault/consent", body, nil)
	if consent.Status != 200 {
		system.t.Fatalf("consent: %d %s", consent.Status, consent.Raw)
	}
	account.CommitGrants()
}

func joinScopes(scopes []string) string {
	joined := ""
	for _, scope := range scopes {
		joined += scope + " "
	}
	return joined
}

// challengeView opens a new authorization request and fetches its view in the browser.
func (system *system) challengeView(browser *testsupport.Browser, clientID string, scopes []string) testsupport.Response {
	system.t.Helper()
	_, challenge := pkce()
	params := system.authorizeParams(testsupport.NewInstall(), challenge, joinScopes(scopes))
	params.Set("client_id", clientID)
	location := system.authorize(params)
	view := browser.Do("GET", "/vault/challenge?login_challenge="+url.QueryEscape(challengeID(location)), nil, nil)
	if view.Status != 200 {
		system.t.Fatalf("challenge view: %d %s", view.Status, view.Raw)
	}
	return view
}

func TestOnlyFirstPartyClientsAreMarkedFirstParty(t *testing.T) {
	system := newSystem(t)
	system.freshAccount("party")
	firstPartyID := "first-" + system.clientID
	if err := testSurreal.CreateClient(firstPartyID, []string{appRedirect}, allScopes(), true); err != nil {
		t.Fatal(err)
	}
	thirdParty := system.challengeView(system.browser, system.clientID, []string{"openid"})
	firstParty := system.challengeView(system.browser, firstPartyID, []string{"openid"})
	if thirdParty.Body["firstParty"] != false || firstParty.Body["firstParty"] != true {
		t.Fatalf("firstParty flags: third %v first %v", thirdParty.Body["firstParty"], firstParty.Body["firstParty"])
	}
}

func TestAThirdPartyClientStaysThirdPartyAfterItsScopesWereGranted(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("returning")
	scopes := []string{"@neoworks/photos:read"}
	system.approve(account, testsupport.NewInstall(), scopes, map[string]string{"@neoworks/photos": "read"})

	view := system.challengeView(system.browser, system.clientID, scopes)
	history, _ := view.Body["history"].(map[string]any)
	if view.Body["firstParty"] != false || history == nil {
		t.Fatalf("a returning third-party app is still third-party and shows its history: %s", view.Raw)
	}
}

func TestTheChallengeShowsWhatTheUserAuthorizedBefore(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("history")
	install := testsupport.NewInstall()
	system.approve(account, install, []string{"openid", "@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})

	view := system.challengeView(system.browser, system.clientID, []string{"@neoworks/photos:write", "@neoworks/calendar:read"})
	history := view.Body["history"].(map[string]any)
	if history["firstAuthorizedAt"] == "" || history["lastAuthorizedAt"] == "" {
		t.Fatalf("missing authorization times: %s", view.Raw)
	}
	heldScopes := history["scopes"].([]any)
	if len(heldScopes) != 2 || !slices.Contains(heldScopes, any("@neoworks/photos:read")) {
		t.Fatalf("held scopes: %v", heldScopes)
	}
	installs := history["installs"].([]any)
	if len(installs) != 1 || installs[0].(map[string]any)["name"] != "Test app" {
		t.Fatalf("installs: %v", installs)
	}
	access := history["access"].([]any)
	if len(access) != 1 || access[0].(map[string]any)["collection"] != "@neoworks/photos" || access[0].(map[string]any)["role"] != "read" {
		t.Fatalf("access: %v", access)
	}
	collections := view.Body["collections"].(map[string]any)
	if collections["@neoworks/photos"] == nil || collections["@neoworks/calendar"] == nil {
		t.Fatalf("titles for requested and held collections: %v", collections)
	}
}

func TestTheHistoryIsNotShownToOtherUsersOrToNobody(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("owner")
	scopes := []string{"@neoworks/photos:read"}
	system.approve(account, testsupport.NewInstall(), scopes, map[string]string{"@neoworks/photos": "read"})

	anonymous := testsupport.NewBrowser(t, system.vault)
	if view := system.challengeView(anonymous, system.clientID, scopes); view.Body["history"] != nil {
		t.Fatalf("history shown without a session: %s", view.Raw)
	}
	system.freshAccount("stranger")
	if view := system.challengeView(system.browser, system.clientID, scopes); view.Body["history"] != nil {
		t.Fatalf("history shown to a user who never authorized the app: %s", view.Raw)
	}
}

func TestANewAuthorizationKeepsAccessInCollectionsItDoesNotMention(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("kept")
	install := testsupport.NewInstall()
	system.approve(account, install, []string{"@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})
	system.approve(account, install, []string{"@neoworks/contacts:read"}, map[string]string{"@neoworks/contacts": "read"})

	view := system.challengeView(system.browser, system.clientID, []string{"@neoworks/contacts:read"})
	heldScopes := view.Body["history"].(map[string]any)["scopes"].([]any)
	if !slices.Contains(heldScopes, any("@neoworks/photos:read")) || !slices.Contains(heldScopes, any("@neoworks/contacts:read")) {
		t.Fatalf("photos access must be kept: %v", heldScopes)
	}
}

func TestRevokingKeptAccessRemovesItFromTheHistory(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("revoke-kept")
	install := testsupport.NewInstall()
	system.approve(account, install, []string{"@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})
	system.approve(account, install, []string{"@neoworks/contacts:read"}, map[string]string{"@neoworks/contacts": "read"})

	_, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/contacts:read"))
	revoked := system.browser.Do("POST", "/vault/consent/revoke", map[string]any{"loginChallenge": challengeID(location), "collection": "@neoworks/photos"}, nil)
	if revoked.Status != 200 {
		t.Fatalf("revoke: %d %s", revoked.Status, revoked.Raw)
	}
	view := system.browser.Do("GET", "/vault/challenge?login_challenge="+url.QueryEscape(challengeID(location)), nil, nil)
	history := view.Body["history"].(map[string]any)
	for _, held := range history["access"].([]any) {
		if held.(map[string]any)["collection"] == "@neoworks/photos" {
			t.Fatalf("photos access must be revoked: %s", view.Raw)
		}
	}
	if slices.Contains(history["scopes"].([]any), any("@neoworks/photos:read")) {
		t.Fatalf("photos scope must be dropped: %v", history["scopes"])
	}
}

func TestRevokeKeptRefusesCollectionsTheRequestStillAsksFor(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("refuse")
	scopes := []string{"@neoworks/photos:read"}
	system.approve(account, testsupport.NewInstall(), scopes, map[string]string{"@neoworks/photos": "read"})
	_, challenge := pkce()
	location := system.authorize(system.authorizeParams(testsupport.NewInstall(), challenge, joinScopes(scopes)))
	revoked := system.browser.Do("POST", "/vault/consent/revoke", map[string]any{"loginChallenge": challengeID(location), "collection": "@neoworks/photos"}, nil)
	if revoked.Status != 400 {
		t.Fatalf("status %d (%s), want 400", revoked.Status, revoked.Raw)
	}
}

func TestRevokeKeptRefusesAUserWhoNeverAuthorizedTheApp(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("holder")
	system.approve(account, testsupport.NewInstall(), []string{"@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})
	system.freshAccount("intruder")
	_, challenge := pkce()
	location := system.authorize(system.authorizeParams(testsupport.NewInstall(), challenge, "openid"))
	revoked := system.browser.Do("POST", "/vault/consent/revoke", map[string]any{"loginChallenge": challengeID(location), "collection": "@neoworks/photos"}, nil)
	if revoked.Status != 404 {
		t.Fatalf("status %d (%s), want 404", revoked.Status, revoked.Raw)
	}
}

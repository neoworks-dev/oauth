package flowtest

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// ownedApp registers a client of the organization with the given standing.
type standing struct {
	verified     bool
	reviewStatus string
	logo         string
	logoHeld     bool
}

func (system *system) createOwnedApp(clientID string, scopes []string, appStanding standing) {
	system.t.Helper()
	err := testSurreal.Exec(`
		UPSERT organization:neoworks SET display_name = 'Neoworks';
		UPSERT handle:neoworks SET kind = 'organization', organization = organization:neoworks;
		UPSERT handle:acme SET kind = 'organization', organization = organization:acme;
		UPSERT organization:acme SET display_name = 'Acme', verified_at = time::now();
		CREATE $client CONTENT {
			name: 'Recipes', description: 'Share recipes', redirect_uris: [$redirect], scopes: $scopes,
			first_party: false, public: true, owner: organization:acme,
			verified: $verified, review_status: $review_status, logo_held: $logo_held
		}`,
		map[string]any{
			"client": models.NewRecordID("client", clientID), "redirect": appRedirect, "scopes": scopes,
			"verified": appStanding.verified, "review_status": appStanding.reviewStatus, "logo_held": appStanding.logoHeld,
		})
	if err != nil {
		system.t.Fatal(err)
	}
	if appStanding.logo != "" {
		err = testSurreal.Exec("UPDATE $client SET logo = $logo",
			map[string]any{"client": models.NewRecordID("client", clientID), "logo": models.NewRecordID("asset", appStanding.logo)})
		if err != nil {
			system.t.Fatal(err)
		}
	}
}

func (system *system) setReviewStatus(clientID string, status string) {
	system.t.Helper()
	err := testSurreal.Exec("UPDATE $client SET review_status = $status",
		map[string]any{"client": models.NewRecordID("client", clientID), "status": status})
	if err != nil {
		system.t.Fatal(err)
	}
}

func TestTheChallengeNamesTheOwnerOfTheAppAndOfEachScope(t *testing.T) {
	system := newSystem(t)
	system.freshAccount("identity")
	if err := testSurreal.PublishCollections([]string{"@acme/recipes"}); err != nil {
		t.Fatal(err)
	}
	clientID := "acme-" + system.clientID
	system.createOwnedApp(clientID, []string{"openid", "@acme/recipes:read", "@neoworks/photos:read"},
		standing{verified: true, reviewStatus: "approved", logo: "logo1"})

	view := system.challengeView(system.browser, clientID, []string{"openid", "@acme/recipes:read", "@neoworks/photos:read"})
	owner := view.Body["owner"].(map[string]any)
	if owner["handle"] != "acme" || owner["displayName"] != "Acme" || owner["kind"] != "organization" || owner["verified"] != true {
		t.Fatalf("owner: %v", owner)
	}
	if view.Body["verified"] != true || view.Body["reviewStatus"] != "approved" || view.Body["description"] != "Share recipes" {
		t.Fatalf("standing: %s", view.Raw)
	}
	if view.Body["logoUrl"] != assetsOrigin+"/assets/logo1" {
		t.Fatalf("logoUrl: %v", view.Body["logoUrl"])
	}
	scopeOwners := view.Body["scopeOwners"].(map[string]any)
	if scopeOwners["acme"].(map[string]any)["displayName"] != "Acme" || scopeOwners["neoworks"] == nil {
		t.Fatalf("scope owners: %v", scopeOwners)
	}
}

func TestAnUnownedUnverifiedAppIsShownAsSuch(t *testing.T) {
	system := newSystem(t)
	system.freshAccount("unowned")
	view := system.challengeView(system.browser, system.clientID, []string{"openid"})
	if view.Body["owner"] != nil || view.Body["verified"] != false || view.Body["logoUrl"] != nil || view.Body["reviewStatus"] != "none" {
		t.Fatalf("an app nobody owns: %s", view.Raw)
	}
}

func TestAHeldLogoIsShownOnlyOnceTheAppIsApproved(t *testing.T) {
	system := newSystem(t)
	system.freshAccount("held")
	clientID := "held-" + system.clientID
	system.createOwnedApp(clientID, []string{"openid"}, standing{reviewStatus: "pending", logo: "lookalike", logoHeld: true})

	if view := system.challengeView(system.browser, clientID, []string{"openid"}); view.Body["logoUrl"] != nil {
		t.Fatalf("a held logo must not reach users: %s", view.Raw)
	}
	system.setReviewStatus(clientID, "approved")
	if view := system.challengeView(system.browser, clientID, []string{"openid"}); view.Body["logoUrl"] == nil {
		t.Fatalf("an approved app shows its logo: %s", view.Raw)
	}
}

func TestASuspendedAppGetsNoNewAuthorizationsAndNoRefreshes(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("suspend")
	issued := system.issueTokens(account)
	refreshToken := issued.Body["refresh_token"].(string)
	_, challenge := pkce()
	pending := system.authorize(system.authorizeParams(testsupport.NewInstall(), challenge, "openid"))

	system.setReviewStatus(system.clientID, "suspended")

	_, newChallenge := pkce()
	params := system.authorizeParams(testsupport.NewInstall(), newChallenge, "openid")
	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
	recorder := httptest.NewRecorder()
	system.oauth.ServeHTTP(recorder, request)
	if location := recorder.Header().Get("Location"); recorder.Code != http.StatusFound || !strings.HasPrefix(location, "/oauth/error") || !strings.Contains(location, "access_denied") {
		t.Fatalf("authorize while suspended: %d %s", recorder.Code, location)
	}
	refreshed := system.refresh(refreshToken)
	if refreshed.Status != http.StatusBadRequest || refreshed.Body["error"] != "unauthorized_client" {
		t.Fatalf("refresh while suspended: %d %s", refreshed.Status, refreshed.Raw)
	}
	view := system.browser.Do("GET", "/vault/challenge?login_challenge="+challengeID(pending), nil, nil)
	if view.Status != http.StatusForbidden || view.Body["error"] != "app_suspended" {
		t.Fatalf("a challenge started before the suspension: %d %s", view.Status, view.Raw)
	}
	consent := system.browser.Do("POST", "/vault/consent", map[string]any{"loginChallenge": challengeID(pending), "scopes": []string{"openid"}}, nil)
	if consent.Status != http.StatusForbidden || consent.Body["error"] != "app_suspended" {
		t.Fatalf("consent while suspended: %d %s", consent.Status, consent.Raw)
	}

	system.setReviewStatus(system.clientID, "approved")
	if lifted := system.refresh(refreshToken); lifted.Status != http.StatusOK {
		t.Fatalf("refresh after the suspension was lifted: %d %s", lifted.Status, lifted.Raw)
	}
}

func TestTheCodeOfASuspendedAppCannotBeExchanged(t *testing.T) {
	system := newSystem(t)
	system.freshAccount("exchange")
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "openid"))
	consent := system.browser.Do("POST", "/vault/consent", map[string]any{"loginChallenge": challengeID(location), "scopes": []string{"openid"}}, nil)
	if consent.Status != http.StatusOK {
		t.Fatalf("consent: %d %s", consent.Status, consent.Raw)
	}
	system.setReviewStatus(system.clientID, "suspended")
	code := strings.Split(strings.Split(consent.Body["redirect"].(string), "code=")[1], "&")[0]
	exchanged := system.exchange(code, verifier)
	if exchanged.Status != http.StatusBadRequest || exchanged.Body["error"] != "unauthorized_client" {
		t.Fatalf("exchange while suspended: %d %s", exchanged.Status, exchanged.Raw)
	}
}

func (system *system) badRefresh(clientID string) testsupport.Response {
	return testsupport.Form(system.oauth, "/oauth/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": "unknown", "client_id": clientID,
	}, nil)
}

func TestTheTokenEndpointIsLimitedPerClientAndIPWithRetryAfter(t *testing.T) {
	system := newSystem(t)
	allowed := 0
	var refused testsupport.Response
	for attempt := 0; attempt < 200; attempt++ {
		response := system.badRefresh(system.clientID)
		if response.Status == http.StatusTooManyRequests {
			refused = response
			break
		}
		allowed++
	}
	if allowed != 60 {
		t.Fatalf("calls before the limit: %d want 60", allowed)
	}
	seconds, err := strconv.Atoi(refused.Header.Get("Retry-After"))
	if err != nil || seconds < 1 || seconds > 60 || refused.Body["error"] != "rate_limited" {
		t.Fatalf("429: Retry-After %q body %s", refused.Header.Get("Retry-After"), refused.Raw)
	}
	requests, limited, err := system.state.UsageToday(t.Context(), system.clientID)
	if err != nil || requests != 61 || limited != 1 {
		t.Fatalf("usage counters: %d requests, %d limited, %v", requests, limited, err)
	}
	if other := system.badRefresh("some-other-client"); other.Status == http.StatusTooManyRequests {
		t.Fatalf("another client is not limited by this client's calls")
	}
}

func TestReviewedAndVerifiedAppsGetHigherTokenLimits(t *testing.T) {
	system := newSystem(t)
	clientID := "trusted-" + system.clientID
	system.createOwnedApp(clientID, []string{"openid"}, standing{verified: true, reviewStatus: "approved"})
	allowed := 0
	for attempt := 0; attempt < 300; attempt++ {
		if system.badRefresh(clientID).Status == http.StatusTooManyRequests {
			break
		}
		allowed++
	}
	if allowed <= 60 {
		t.Fatalf("a verified, approved app is held to the default limit: %d", allowed)
	}
}

func TestAuthorizeIsLimitedToo(t *testing.T) {
	system := newSystem(t)
	allowed := 0
	for attempt := 0; attempt < 200; attempt++ {
		_, challenge := pkce()
		params := system.authorizeParams(testsupport.NewInstall(), challenge, "openid")
		request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
		recorder := httptest.NewRecorder()
		system.oauth.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusTooManyRequests {
			if recorder.Header().Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			break
		}
		allowed++
	}
	if allowed != 60 {
		t.Fatalf("authorize calls before the limit: %d want 60", allowed)
	}
}

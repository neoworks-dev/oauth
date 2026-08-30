package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	authmiddleware "github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// ── Fakes ─────────────────────────────────────────────────────────────────────

type fakeClients struct {
	redirectURIs []string
}

func (f fakeClients) GetClient(context.Context, string) (*oauth.Client, error) {
	if f.redirectURIs == nil {
		return nil, errors.New("client not found")
	}
	return &oauth.Client{RedirectURIs: f.redirectURIs}, nil
}

type fakeGoogle struct {
	account *database.GoogleAccount

	linked        *database.LinkGoogleAccountParams
	setToken      string
	setExpiry     time.Time
	unlinked      bool
	savedCalendar *database.SaveGoogleCalendarLinkParams
	savedEvents   []database.GoogleEventLink
}

func (f *fakeGoogle) LinkAccount(_ context.Context, _ models.RecordID, p database.LinkGoogleAccountParams) error {
	f.linked = &p
	return nil
}

func (f *fakeGoogle) Account(context.Context, models.RecordID) (*database.GoogleAccount, error) {
	if f.account == nil {
		return nil, database.ErrNotFound
	}
	return f.account, nil
}

func (f *fakeGoogle) SetAccessToken(_ context.Context, _ models.RecordID, token string, expiresAt time.Time) error {
	f.setToken = token
	f.setExpiry = expiresAt
	return nil
}

func (f *fakeGoogle) Unlink(context.Context, models.RecordID) error {
	f.unlinked = true
	return nil
}

func (f *fakeGoogle) CalendarLinks(context.Context, models.RecordID) ([]database.GoogleCalendarLink, error) {
	return []database.GoogleCalendarLink{}, nil
}

func (f *fakeGoogle) SaveCalendarLink(_ context.Context, _ models.RecordID, p database.SaveGoogleCalendarLinkParams) error {
	f.savedCalendar = &p
	return nil
}

func (f *fakeGoogle) DeleteCalendarLink(context.Context, models.RecordID, string) error { return nil }

func (f *fakeGoogle) EventLinks(context.Context, models.RecordID, string) ([]database.GoogleEventLink, error) {
	return []database.GoogleEventLink{}, nil
}

func (f *fakeGoogle) SaveEventLinks(_ context.Context, _ models.RecordID, links []database.GoogleEventLink) error {
	f.savedEvents = links
	return nil
}

func (f *fakeGoogle) DeleteEventLink(context.Context, models.RecordID, string) error { return nil }

// fakeSessions stands in for the sso_session cookie. An empty userID means no
// session.
type fakeSessions struct {
	userID string
}

func (f fakeSessions) UserID(*http.Request) (string, error) {
	if f.userID == "" {
		return "", errors.New("no session")
	}
	return f.userID, nil
}

// fakeGoogleAPI is Google's token and revoke endpoints. tokenStatus/tokenBody
// decide what the token endpoint answers.
type fakeGoogleAPI struct {
	server      *httptest.Server
	tokenStatus int
	tokenBody   string
	tokenForms  []url.Values
	revoked     []string
}

func newFakeGoogleAPI(t *testing.T) *fakeGoogleAPI {
	t.Helper()
	api := &fakeGoogleAPI{tokenStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		api.tokenForms = append(api.tokenForms, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(api.tokenStatus)
		_, _ = w.Write([]byte(api.tokenBody))
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		api.revoked = append(api.revoked, r.PostForm.Get("token"))
		w.WriteHeader(http.StatusOK)
	})
	api.server = httptest.NewServer(mux)
	t.Cleanup(api.server.Close)
	return api
}

// ── Harness ───────────────────────────────────────────────────────────────────

type harness struct {
	handler *Handler
	router  chi.Router
	google  *fakeGoogle
	api     *fakeGoogleAPI
}

func newHarness(t *testing.T, sessions Sessions, clients clientStore) *harness {
	t.Helper()
	api := newFakeGoogleAPI(t)
	store := &fakeGoogle{}
	handler := NewHandler(clients, store, sessions, Config{
		ClientID:     "google-client",
		ClientSecret: "google-secret",
		RedirectURI:  "https://oauth.example/google/callback",
		AuthURL:      "https://accounts.example/authorize",
		TokenURL:     api.server.URL + "/token",
		RevokeURL:    api.server.URL + "/revoke",
		APIBase:      api.server.URL,
	})

	router := chi.NewRouter()
	handler.Register(router)
	handler.RegisterAuthenticated(router)
	return &harness{handler: handler, router: router, google: store, api: api}
}

// authed builds a request carrying a verified access token's claims, as the JWT
// middleware would have attached them.
func authed(method, target string, body string, scopes ...string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	claim := &oauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "user-1"},
		Scope:            scopes,
	}
	return request.WithContext(authmiddleware.NewContextWithClaim(request.Context(), claim))
}

func idToken(sub, email string) string {
	payload, _ := json.Marshal(map[string]string{"sub": sub, "email": email})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func linkedAccount(expiresAt time.Time) *database.GoogleAccount {
	return &database.GoogleAccount{
		GoogleSub:    "google-sub-1",
		Email:        "someone@example.com",
		RefreshToken: "stored-refresh",
		AccessToken:  "stored-access",
		ExpiresAt:    &expiresAt,
	}
}

// ── Scope gate ────────────────────────────────────────────────────────────────

// Without the scope check these routes would be an open Google OAuth proxy for
// anyone holding any neoworks access token.
func TestAccessTokenRequiresGoogleLinkScope(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
	h.google.account = linkedAccount(time.Now().Add(time.Hour))

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodGet, "/google/token", "", "calendar:read"))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestAccessTokenRejectsUnauthenticatedCaller(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
	h.google.account = linkedAccount(time.Now().Add(time.Hour))

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/google/token", nil))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

// Every Vault-facing route is gated, not just the one that mints tokens.
func TestEveryAuthenticatedRouteChecksTheScope(t *testing.T) {
	routes := []struct {
		method string
		target string
		body   string
	}{
		{http.MethodGet, "/google/link", ""},
		{http.MethodDelete, "/google/link", ""},
		{http.MethodGet, "/google/token", ""},
		{http.MethodGet, "/google/calendars", ""},
		{http.MethodGet, "/google/calendar-links", ""},
		{http.MethodPut, "/google/calendar-links", `{"space_id":"x","google_calendar_id":"y"}`},
		{http.MethodDelete, "/google/calendar-links?google_calendar_id=y", ""},
		{http.MethodGet, "/google/event-links", ""},
		{http.MethodPut, "/google/event-links", `{"links":[]}`},
		{http.MethodDelete, "/google/event-links?uid=u", ""},
	}

	for _, route := range routes {
		h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
		h.google.account = linkedAccount(time.Now().Add(time.Hour))

		recorder := httptest.NewRecorder()
		h.router.ServeHTTP(recorder, authed(route.method, route.target, route.body))

		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s %s: status = %d, want 403", route.method, route.target, recorder.Code)
		}
	}
}

// ── Access token ──────────────────────────────────────────────────────────────

func TestAccessTokenReusesAStillValidToken(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
	h.google.account = linkedAccount(time.Now().Add(time.Hour))

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodGet, "/google/token", "", LinkScope))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if len(h.api.tokenForms) != 0 {
		t.Error("a valid token should not be refreshed")
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	if body.AccessToken != "stored-access" {
		t.Errorf("access_token = %q, want stored-access", body.AccessToken)
	}
}

func TestAccessTokenRefreshesAnExpiredToken(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
	h.google.account = linkedAccount(time.Now().Add(-time.Minute))
	h.api.tokenBody = `{"access_token":"fresh-access","expires_in":3600}`

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodGet, "/google/token", "", LinkScope))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if len(h.api.tokenForms) != 1 {
		t.Fatalf("token endpoint called %d times, want 1", len(h.api.tokenForms))
	}
	form := h.api.tokenForms[0]
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "stored-refresh" {
		t.Errorf("refresh form = %v", form)
	}
	// Written back so parallel devices reuse it instead of each refreshing.
	if h.google.setToken != "fresh-access" {
		t.Errorf("stored access token = %q, want fresh-access", h.google.setToken)
	}
}

// A dead Google grant is not the caller's token being wrong, so it must not read
// as 401 — the app has to prompt for a fresh consent instead of a fresh sign-in.
func TestAccessTokenReportsARevokedGrantAsConflict(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
	h.google.account = linkedAccount(time.Now().Add(-time.Minute))
	h.api.tokenStatus = http.StatusBadRequest
	h.api.tokenBody = `{"error":"invalid_grant"}`

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodGet, "/google/token", "", LinkScope))

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAccessTokenReportsAnUnlinkedAccount(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodGet, "/google/token", "", LinkScope))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

// ── Consent flow ──────────────────────────────────────────────────────────────

func TestConnectRedirectsToGoogleAndSetsState(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/google/connect?client_id=app", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	target, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location is not a URL: %v", err)
	}
	query := target.Query()
	// offline + consent is what guarantees a refresh token on every link.
	if query.Get("access_type") != "offline" || query.Get("prompt") != "consent" {
		t.Errorf("authorize query = %v", query)
	}
	if !strings.Contains(query.Get("scope"), CalendarScope) {
		t.Errorf("scope = %q, want it to include the calendar scope", query.Get("scope"))
	}
	if stateCookieValue(recorder) == "" {
		t.Error("no state cookie was set")
	}
	if stateCookieValue(recorder) != query.Get("state") {
		t.Error("state cookie and state parameter differ")
	}
}

func TestConnectRedirectsAnAnonymousVisitorToLogin(t *testing.T) {
	h := newHarness(t, fakeSessions{}, fakeClients{})

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/google/connect", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	if strings.Contains(recorder.Header().Get("Location"), "accounts.example") {
		t.Error("an anonymous visitor must not reach the Google consent screen")
	}
}

// The state cookie is the CSRF check: without it an attacker could hand the user
// a callback URL carrying their own authorization code.
func TestCallbackRejectsAMismatchedState(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{
		redirectURIs: []string{"https://app.example/callback"},
	})

	request := httptest.NewRequest(http.MethodGet, "/google/callback?code=abc&state=attacker", nil)
	request.AddCookie(&http.Cookie{Name: stateCookie, Value: "genuine"})

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, request)

	if h.google.linked != nil {
		t.Fatal("a mismatched state must not link an account")
	}
	if !strings.Contains(recorder.Body.String(), "invalid_state") {
		t.Error("the callback page should report invalid_state")
	}
}

func TestCallbackRejectsAMissingStateCookie(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{
		redirectURIs: []string{"https://app.example/callback"},
	})

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/google/callback?code=abc&state=anything", nil))

	if h.google.linked != nil {
		t.Fatal("a callback without a state cookie must not link an account")
	}
}

func TestCallbackLinksTheAccount(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{
		redirectURIs: []string{"https://app.example/callback", "https://app.example/other"},
	})
	h.api.tokenBody = `{"access_token":"a1","refresh_token":"r1","expires_in":3600,` +
		`"scope":"openid email https://www.googleapis.com/auth/calendar",` +
		`"id_token":"` + idToken("google-sub-1", "someone@example.com") + `"}`

	request := httptest.NewRequest(http.MethodGet, "/google/callback?code=abc&state=genuine", nil)
	request.AddCookie(&http.Cookie{Name: stateCookie, Value: "genuine"})
	request.AddCookie(&http.Cookie{Name: clientCookie, Value: "app"})

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, request)

	if h.google.linked == nil {
		t.Fatalf("no account was linked: %s", recorder.Body.String())
	}
	if h.google.linked.GoogleSub != "google-sub-1" || h.google.linked.Email != "someone@example.com" {
		t.Errorf("linked identity = %+v", *h.google.linked)
	}
	if h.google.linked.RefreshToken != "r1" {
		t.Errorf("refresh token = %q, want r1", h.google.linked.RefreshToken)
	}
	// The result goes to the client's registered origins only — one entry per
	// distinct origin, not per redirect URI.
	body := recorder.Body.String()
	if strings.Count(body, "https://app.example") != 1 {
		t.Errorf("allowed origins are wrong:\n%s", body)
	}
}

// An unknown client must not fall back to a permissive allowlist.
func TestCallbackPostsNowhereForAnUnknownClient(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})

	request := httptest.NewRequest(http.MethodGet, "/google/callback?error=access_denied", nil)
	request.AddCookie(&http.Cookie{Name: clientCookie, Value: "ghost"})

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, request)

	if !strings.Contains(recorder.Body.String(), "[]") {
		t.Error("an unknown client should render an empty allowed-origins list")
	}
}

// ── Unlink ────────────────────────────────────────────────────────────────────

func TestUnlinkRevokesAtGoogleAndDropsTheRows(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
	h.google.account = linkedAccount(time.Now().Add(time.Hour))

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodDelete, "/google/link", "", LinkScope))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if len(h.api.revoked) != 1 || h.api.revoked[0] != "stored-refresh" {
		t.Errorf("revoked = %v, want the stored refresh token", h.api.revoked)
	}
	if !h.google.unlinked {
		t.Error("the local rows were not dropped")
	}
}

// A user who already revoked the grant in their Google settings must still be
// able to clear the rows here.
func TestUnlinkSucceedsWhenGoogleRefusesTheRevoke(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})
	h.google.account = linkedAccount(time.Now().Add(time.Hour))
	h.api.server.Close()

	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodDelete, "/google/link", "", LinkScope))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !h.google.unlinked {
		t.Error("the local rows were not dropped")
	}
}

// ── Sync state ────────────────────────────────────────────────────────────────

// An unrecognized role degrades to reader, which is pull-only: pushing to a
// calendar the user cannot write 403s forever.
func TestCalendarLinkFallsBackToReader(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})

	body := `{"space_id":"0199a0f0-0000-7000-8000-000000000000",` +
		`"google_calendar_id":"primary","access_role":"nonsense"}`
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodPut, "/google/calendar-links", body, LinkScope))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if h.google.savedCalendar.AccessRole != "reader" {
		t.Errorf("access_role = %q, want reader", h.google.savedCalendar.AccessRole)
	}
	// Absent `enabled` means enabled: linking a calendar is the act of enabling it.
	if !h.google.savedCalendar.Enabled {
		t.Error("a link with no explicit enabled flag should be enabled")
	}
}

func TestEventLinksRejectAnIncompleteJoin(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})

	body := `{"links":[{"uid":"u1","google_calendar_id":"primary"}]}`
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodPut, "/google/event-links", body, LinkScope))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if h.google.savedEvents != nil {
		t.Error("an incomplete batch must not be written")
	}
}

func TestEventLinksAreSaved(t *testing.T) {
	h := newHarness(t, fakeSessions{userID: "user-1"}, fakeClients{})

	body := `{"links":[{"uid":"u1","google_calendar_id":"primary",` +
		`"google_event_id":"g1","content_hash":"h1"}]}`
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, authed(http.MethodPut, "/google/event-links", body, LinkScope))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if len(h.google.savedEvents) != 1 || h.google.savedEvents[0].GoogleEventID != "g1" {
		t.Errorf("saved links = %+v", h.google.savedEvents)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func stateCookieValue(recorder *httptest.ResponseRecorder) string {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == stateCookie {
			return cookie.Value
		}
	}
	return ""
}

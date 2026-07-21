package handlers

import (
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/shared"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

type ConsentHandler struct {
	redis    *cache.RedisStore
	store    *database.SurrealStore
	issuer   *oauth.TokenIssuer
	loginURL string
}

func NewConsentHandler(redis *cache.RedisStore, store *database.SurrealStore, issuer *oauth.TokenIssuer, loginURL string) *ConsentHandler {
	return &ConsentHandler{
		redis:    redis,
		store:    store,
		issuer:   issuer,
		loginURL: loginURL,
	}
}

func (h *ConsentHandler) Register(r chi.Router) {
	r.Get("/oauth/consent", h.serveConsent)
	r.Post("/oauth/consent", h.handleConsent)
}

//go:embed templates/consent.html
var consentTemplate string
var consentTmpl = template.Must(template.New("consent").Parse(consentTemplate))

// scopeCatalog maps raw OAuth scope strings to the labels we show the user.
// Unknown scopes fall through to their raw name so nothing ever renders blank.
var scopeCatalog = map[string]scopeView{
	"openid":  {Name: "Verify your identity"},
	"profile": {Name: "Access your profile", Description: "Your name, username, and avatar"},
	"email":   {Name: "Access your email address"},
	"offline": {Name: "Stay signed in", Description: "Maintain access while you're not using the app"},
	// AI runtime scopes gate the local neod daemon. The tool scopes let the agent
	// touch your machine and are far more sensitive than plain chat/complete.
	"ai:chat":     {Name: "Chat with AI", Description: "Send messages to the local or cloud AI"},
	"ai:complete": {Name: "AI text completion", Description: "Autocomplete text and code"},
	"ai:fsread":   {Name: "Let AI read app files", Description: "Read files within the app's data directory"},
	"ai:fswrite":  {Name: "Let AI write app files", Description: "Write files in the app's data directory (asks each time)"},
	"ai:webfetch": {Name: "Let AI fetch web pages", Description: "Fetch content from URLs on your behalf"},
	"ai:bash":     {Name: "Let AI run commands", Description: "Run sandboxed shell commands on your machine (asks each time)"},
}

type scopeView struct {
	Name        string
	Description string
}

func buildScopeView(scopes []string) []scopeView {
	out := make([]scopeView, 0, len(scopes))
	for _, s := range scopes {
		if v, ok := scopeCatalog[s]; ok {
			out = append(out, v)
		} else {
			out = append(out, scopeView{Name: s})
		}
	}
	return out
}

func userInitial(email string) string {
	if email == "" {
		return "?"
	}
	return strings.ToUpper(email[:1])
}

func clearLoginSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "login_session",
		Value:    "",
		Path:     "/oauth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// resolveSession pulls the logged-in user out of the login_session cookie that
// the login handler set on its way here. If anything is off (missing cookie,
// bad token, user vanished), we return an error and the caller bounces to /login.
func (h *ConsentHandler) resolveSession(r *http.Request) (*oauth.User, error) {
	cookie, err := r.Cookie("login_session")
	if err != nil {
		return nil, err
	}
	userID, err := h.issuer.ValidateSessionToken(cookie.Value)
	if err != nil {
		return nil, err
	}
	return h.store.GetUserByID(r.Context(), userID)
}

func (h *ConsentHandler) serveConsent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	loginChallengeID := r.URL.Query().Get("login_challenge")
	if loginChallengeID == "" {
		shared.RestartLogin(w, r, h.loginURL)
		return
	}

	user, err := h.resolveSession(r)
	if err != nil {
		// No valid login_session — send them back to login, preserving the challenge.
		http.Redirect(w, r, "/auth/login?login_challenge="+url.QueryEscape(loginChallengeID), http.StatusFound)
		return
	}

	loginChallenge, err := h.redis.GetLoginChallenge(r.Context(), loginChallengeID)
	if err != nil {
		shared.RestartLogin(w, r, h.loginURL)
		return
	}

	client, err := h.store.GetClient(r.Context(), loginChallenge.ClientID)
	if err != nil {
		http.Error(w, "Invalid client", http.StatusUnauthorized)
		return
	}

	// If the user already granted these scopes to this client, skip the prompt.
	// Keeps repeat authorizations friction-free (same behavior Google / GitHub have).
	if grant, err := h.store.GetGrant(r.Context(), user.ID, client.ID); err == nil &&
		grant.Enabled && containsAllScopes(grant.Scopes, loginChallenge.Scopes) {
		h.issueCodeAndRedirect(w, r, user, client, loginChallenge)
		return
	}

	_ = consentTmpl.Execute(w, map[string]any{
		"LoginChallenge": loginChallengeID,
		"AppName":        client.ID,
		"UserEmail":      user.Email,
		"UserInitial":    userInitial(user.Email),
		"Scopes":         buildScopeView(loginChallenge.Scopes),
		"Error":          "",
	})
}

func (h *ConsentHandler) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	loginChallengeID := r.FormValue("login_challenge")
	action := r.FormValue("action")

	user, err := h.resolveSession(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login?login_challenge="+url.QueryEscape(loginChallengeID), http.StatusFound)
		return
	}

	loginChallenge, err := h.redis.GetLoginChallenge(r.Context(), loginChallengeID)
	if err != nil {
		shared.RestartLogin(w, r, h.loginURL)
		return
	}

	client, err := h.store.GetClient(r.Context(), loginChallenge.ClientID)
	if err != nil {
		http.Error(w, "Invalid client", http.StatusUnauthorized)
		return
	}

	// Either branch ends the consent step — burn the challenge and the short-lived cookie.
	defer h.redis.DeleteLoginChallenge(r.Context(), loginChallenge.ID)
	defer clearLoginSession(w)

	if action != "allow" {
		// RFC 6749 §4.1.2.1: user denied → redirect back with error=access_denied.
		redirect := loginChallenge.RedirectURI +
			"?error=access_denied" +
			"&error_description=" + url.QueryEscape("The user denied the authorization request") +
			"&state=" + url.QueryEscape(loginChallenge.State)
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	if err := h.store.UpsertGrant(r.Context(), &oauth.Grant{
		User:    user.ID,
		Client:  client.ID,
		Scopes:  loginChallenge.Scopes,
		Enabled: true,
	}); err != nil {
		http.Error(w, "Failed to save grant", http.StatusInternalServerError)
		return
	}

	h.issueCodeAndRedirect(w, r, user, client, loginChallenge)
}

// issueCodeAndRedirect mints the authorization code and bounces the user back
// to the client's redirect_uri. Mirrors the auto-grant path in LoginHandler —
// worth extracting into a shared helper on a shared struct at some point.
func (h *ConsentHandler) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, user *oauth.User, client *oauth.Client, lc *oauth.LoginChallenge) {
	authCode := utils.GenerateRandomString(32)
	if err := h.redis.SaveAuthCode(r.Context(), oauth.AuthCode{
		Code:                authCode,
		UserID:              user.ID,
		ClientID:            client.ID,
		Scopes:              lc.Scopes,
		RedirectURI:         lc.RedirectURI,
		CodeChallenge:       lc.CodeChallenge,
		CodeChallengeMethod: lc.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}); err != nil {
		http.Error(w, "Failed to save authorization code", http.StatusInternalServerError)
		return
	}

	redirect := lc.RedirectURI +
		"?code=" + url.QueryEscape(authCode) +
		"&state=" + url.QueryEscape(lc.State)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func containsAllScopes(granted, requested []string) bool {
	set := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		set[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

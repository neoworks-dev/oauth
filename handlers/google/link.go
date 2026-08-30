package google

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/oauth/handlers/origins"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

//go:embed templates/google-callback.html
var callbackTemplate string
var callbackTmpl = template.Must(template.New("google-callback").Parse(callbackTemplate))

const (
	stateCookie  = "google_oauth_state"
	clientCookie = "google_oauth_client"
	cookiePath   = "/google"
	// Long enough for a consent screen, short enough that an abandoned flow does
	// not leave a usable state around.
	flowCookieSeconds = 600
)

// ── Consent flow ──────────────────────────────────────────────────────────────

// connect starts the Google consent flow. It is opened as a popup from the app,
// which makes it a top-level navigation on this origin — so the sso_session
// cookie is first-party here and a bearer token is neither available nor needed.
func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	if !h.config.Enabled() {
		http.Error(w, "Google linking is not configured on this server.", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.sessions.UserID(r); err != nil {
		// apps/web owns the login UI; the same redirect the account pages use.
		http.Redirect(w, r, config.ServiceURL("")+"/dashboard", http.StatusFound)
		return
	}

	state, err := randomState()
	if err != nil {
		http.Error(w, "Could not start the Google flow.", http.StatusInternalServerError)
		return
	}

	setCookie(w, stateCookie, state, flowCookieSeconds)
	setCookie(w, clientCookie, r.URL.Query().Get("client_id"), flowCookieSeconds)
	http.Redirect(w, r, h.authorizeURL(state), http.StatusFound)
}

func (h *Handler) authorizeURL(state string) string {
	query := url.Values{
		"client_id":     {h.config.ClientID},
		"redirect_uri":  {h.config.RedirectURI},
		"response_type": {"code"},
		"scope":         {"openid email " + CalendarScope},
		"access_type":   {"offline"},
		// Force the consent screen on every link. Google returns a refresh token
		// only on the first grant otherwise, so a re-link after the stored token
		// was dropped would produce an account this server cannot refresh.
		"prompt":                 {"consent"},
		"include_granted_scopes": {"true"},
		"state":                  {state},
	}
	return h.config.authURL() + "?" + query.Encode()
}

// callback finishes the flow and reports the outcome to the window that opened
// it. The page renders regardless of the result — a popup that dies silently on
// failure leaves the app waiting forever.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	allowed := h.allowedOrigins(r.Context(), cookieValue(r, clientCookie))
	clearCookie(w, stateCookie)
	clearCookie(w, clientCookie)

	h.renderCallback(w, allowed, h.linkFromCallback(r))
}

// linkFromCallback performs the exchange and stores the account, returning an
// error code for the callback page or "" on success. The codes are for the app's
// own copy — nothing here is shown to the user raw.
func (h *Handler) linkFromCallback(r *http.Request) string {
	if denied := r.URL.Query().Get("error"); denied != "" {
		return denied
	}
	if !stateMatches(r) {
		return "invalid_state"
	}
	userID, err := h.sessions.UserID(r)
	if err != nil {
		return "not_signed_in"
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return "missing_code"
	}

	tokens, err := h.exchangeCode(r.Context(), code)
	if err != nil {
		slog.Error("google code exchange", "error", err)
		return "exchange_failed"
	}
	who := identityFromIDToken(tokens.IDToken)
	if who.Sub == "" {
		return "missing_identity"
	}
	if err := h.storeLink(r.Context(), userID, who, tokens); err != nil {
		slog.Error("store google link", "error", err)
		return "store_failed"
	}
	return ""
}

func (h *Handler) storeLink(ctx context.Context, userID string, who identity, tokens *tokenResponse) error {
	return h.google.LinkAccount(ctx, models.NewRecordID("user", userID), database.LinkGoogleAccountParams{
		GoogleSub:    who.Sub,
		Email:        who.Email,
		RefreshToken: tokens.RefreshToken,
		AccessToken:  tokens.AccessToken,
		ExpiresAt:    expiryOf(tokens),
		Scopes:       splitScopes(tokens.Scope),
	})
}

type callbackData struct {
	AllowedOriginsJSON template.JS
	ResultJSON         template.JS
}

// renderCallback posts the outcome to every origin the opening client registered
// for sign-in — the same trust source the unlock window uses. The message
// carries no secret, only whether the link succeeded.
func (h *Handler) renderCallback(w http.ResponseWriter, allowed []string, failure string) {
	originsJSON, _ := json.Marshal(allowed)
	resultJSON, _ := json.Marshal(map[string]any{
		"type":  "google-link-result",
		"ok":    failure == "",
		"error": failure,
	})

	var buf bytes.Buffer
	if err := callbackTmpl.Execute(&buf, callbackData{
		AllowedOriginsJSON: template.JS(originsJSON),
		ResultJSON:         template.JS(resultJSON),
	}); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// allowedOrigins are the origins of the opening client's registered redirect
// URIs. An unknown client yields none, so the page posts nowhere rather than
// falling back to a permissive default.
func (h *Handler) allowedOrigins(ctx context.Context, clientID string) []string {
	if clientID == "" {
		return []string{}
	}
	client, err := h.clients.GetClient(ctx, clientID)
	if err != nil {
		return []string{}
	}
	return origins.FromRedirectURIs(clientRedirectURIs(client))
}

func clientRedirectURIs(client *oauth.Client) []string {
	if client == nil {
		return nil
	}
	return client.RedirectURIs
}

// ── Link status ───────────────────────────────────────────────────────────────

// linkStatus answers whether a Google account is linked, and which. It returns
// no token: the access token has its own route so that the one place minting
// credentials is explicit.
func (h *Handler) linkStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	account, err := h.google.Account(r.Context(), user)
	if errors.Is(err, database.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"linked": false})
		return
	}
	if err != nil {
		slog.Error("google link status", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"linked":    true,
		"email":     account.Email,
		"scopes":    account.Scopes,
		"linked_at": account.LinkedAt,
	})
}

// unlink revokes at Google and drops the account plus every piece of sync state
// derived from it.
func (h *Handler) unlink(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	h.revokeGrant(r.Context(), user)
	if err := h.google.Unlink(r.Context(), user); err != nil {
		slog.Error("unlink google account", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"linked": false})
}

// revokeGrant tells Google to drop the grant. Best effort on purpose: a user who
// already revoked it from their Google account settings must still be able to
// clear the rows here.
func (h *Handler) revokeGrant(ctx context.Context, user models.RecordID) {
	account, err := h.google.Account(ctx, user)
	if err != nil || account.RefreshToken == "" {
		return
	}
	if err := h.revokeAtGoogle(ctx, account.RefreshToken); err != nil {
		slog.Warn("revoke google grant", "error", err)
	}
}

// ── Flow cookies ──────────────────────────────────────────────────────────────

func randomState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// stateMatches is the CSRF check: the state Google echoed back must equal the
// one this browser was given. Compared in constant time so a mismatch leaks no
// prefix.
func stateMatches(r *http.Request) bool {
	stored := cookieValue(r, stateCookie)
	returned := r.URL.Query().Get("state")
	if stored == "" || returned == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(returned)) == 1
}

func cookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		// Lax, not Strict: the callback arrives as a top-level redirect from
		// accounts.google.com, and Strict would withhold the cookie exactly there.
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	setCookie(w, name, "", -1)
}

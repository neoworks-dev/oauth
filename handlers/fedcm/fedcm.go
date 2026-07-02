// Package fedcm implements the IdP side of the browser FedCM API
// (Federated Credential Management), used by the "Sign in with NeoWorks" prompt
// on Chromium. FedCM lets the browser mediate sign-in without third-party
// cookies: the browser fetches the endpoints below itself (marked by the
// Sec-Fetch-Dest: webidentity header) and draws the account-chooser UI.
//
// Endpoints (per the FedCM spec):
//
//	GET  /.well-known/web-identity   list of allowed provider config URLs
//	GET  /fedcm/config.json          IdP config (endpoint URLs + branding)
//	GET  /fedcm/accounts             the signed-in account(s), from sso_session
//	GET  /fedcm/client-metadata      privacy policy / terms URLs
//	POST /fedcm/assertion            mint an ID token for the chosen account
//
// Browsers without FedCM fall back to the iframe probe in handlers/session.
package fedcm

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"

	"github.com/neoworks/oauth/handlers/origins"
)

// store is the slice of the user/client registry this handler needs. Satisfied
// by *database.SurrealStore; an interface keeps the handler unit-testable.
type store interface {
	GetUserByID(ctx context.Context, id string) (*oauth.User, error)
	GetClient(ctx context.Context, id string) (*oauth.Client, error)
}

type Handler struct {
	store     store
	redis     *cache.RedisStore
	issuer    *oauth.TokenIssuer
	issuerURL string
}

func NewHandler(s store, redis *cache.RedisStore, issuer *oauth.TokenIssuer, issuerURL string) *Handler {
	return &Handler{
		store:     s,
		redis:     redis,
		issuer:    issuer,
		issuerURL: strings.TrimRight(issuerURL, "/"),
	}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/.well-known/web-identity", h.serveWellKnown)
	r.Get("/fedcm/config.json", h.serveConfig)
	r.Get("/fedcm/accounts", h.serveAccounts)
	r.Get("/fedcm/client-metadata", h.serveClientMetadata)
	r.Post("/fedcm/assertion", h.serveAssertion)
}

// serveWellKnown advertises which provider config URLs are valid for this IdP.
func (h *Handler) serveWellKnown(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"provider_urls": []string{h.issuerURL + "/fedcm/config.json"},
	})
}

func (h *Handler) serveConfig(w http.ResponseWriter, r *http.Request) {
	if !isWebIdentityRequest(r) {
		http.Error(w, "not a FedCM request", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"accounts_endpoint":        "/fedcm/accounts",
		"client_metadata_endpoint": "/fedcm/client-metadata",
		"id_assertion_endpoint":    "/fedcm/assertion",
		"branding": map[string]any{
			"background_color": "#0b0b0d",
			"color":            "#fafafa",
			"icons": []map[string]any{
				{"url": h.issuerURL + "/auth/static/icon.svg", "size": 100},
			},
		},
	})
}

// serveAccounts returns the currently signed-in account from the SSO session.
// The browser sends this request with credentials; an empty list means the
// browser shows nothing (user is not signed in to NeoWorks).
func (h *Handler) serveAccounts(w http.ResponseWriter, r *http.Request) {
	if !isWebIdentityRequest(r) {
		http.Error(w, "not a FedCM request", http.StatusBadRequest)
		return
	}

	user := h.currentUser(r)
	if user == nil {
		writeJSON(w, map[string]any{"accounts": []any{}})
		return
	}

	writeJSON(w, map[string]any{
		"accounts": []map[string]any{
			{
				"id":    userIDString(user),
				"email": user.Email,
				"name":  strings.TrimSpace(user.FirstName + " " + user.LastName),
			},
		},
	})
}

func (h *Handler) serveClientMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"privacy_policy_url":   h.issuerURL + "/privacy",
		"terms_of_service_url": h.issuerURL + "/terms",
	})
}

// serveAssertion mints an ID token for the account the user picked in the
// browser UI. The RP (client) origin must be allow-listed, and the request must
// carry a valid SSO session.
func (h *Handler) serveAssertion(w http.ResponseWriter, r *http.Request) {
	if !isWebIdentityRequest(r) {
		http.Error(w, "not a FedCM request", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	clientID := r.FormValue("client_id")
	if clientID == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}

	// The RP origin must be one this client registered as a redirect-URI origin.
	origin := r.Header.Get("Origin")
	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil || !origins.Allows(client.RedirectURIs, origin) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	// FedCM assertion responses are read cross-origin by the browser on behalf
	// of the RP, so they need credentialed CORS for the RP's origin.
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	user := h.currentUser(r)
	if user == nil {
		http.Error(w, `{"error":"not_signed_in"}`, http.StatusUnauthorized)
		return
	}

	token, err := h.issuer.IssueIDToken(
		userIDString(user),
		clientID,
		user.Email,
		strings.TrimSpace(user.FirstName+" "+user.LastName),
		r.FormValue("nonce"),
	)
	if err != nil {
		http.Error(w, `{"error":"token_error"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"token": token})
}

// currentUser resolves the SSO session cookie to a user, or nil when absent.
func (h *Handler) currentUser(r *http.Request) *oauth.User {
	cookie, err := r.Cookie("sso_session")
	if err != nil {
		return nil
	}
	userID, err := h.redis.GetSSOSession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}
	user, err := h.store.GetUserByID(r.Context(), userID)
	if err != nil {
		return nil
	}
	return user
}

// isWebIdentityRequest verifies the browser's FedCM marker header, which cannot
// be forged by page script — it rejects ordinary cross-site fetches.
func isWebIdentityRequest(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Dest") == "webidentity"
}

func userIDString(user *oauth.User) string {
	if user.ID == nil {
		return ""
	}
	if id, ok := user.ID.ID.(string); ok {
		return id
	}
	return ""
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

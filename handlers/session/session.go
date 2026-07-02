// Package session powers the "Sign in with NeoWorks" prompt (One Tap style).
// It exposes the current SSO session to first-party callers so the SDK can
// decide whether to show a sign-in toast:
//
//   - GET /session: same-origin JSON of the current SSO session. Reads the
//     sso_session cookie; returns {authenticated:false} when there is none.
//   - GET /auth/session-bridge: an HTML page the SDK loads in a hidden iframe.
//     It fetches /session same-origin (so the sso_session cookie is first-party
//     here) and postMessages the result to the embedding app, but only to an
//     allow-listed parent origin.
//
// Chrome uses FedCM instead (see handlers/fedcm); this iframe path is the
// fallback for browsers without FedCM.
package session

import (
	"context"
	_ "embed"
	"encoding/json"
	"html/template"
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
	store store
	redis *cache.RedisStore
}

func NewHandler(s store, redis *cache.RedisStore) *Handler {
	return &Handler{store: s, redis: redis}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/session", h.serveSession)
	r.Get("/auth/session-bridge", h.serveBridge)
}

type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Email         string `json:"email,omitempty"`
	Name          string `json:"name,omitempty"`
}

// serveSession reports the current SSO session. Same-origin only: it is read by
// the bridge page below, never exposed cross-origin, so the session state of a
// logged-in user is not leaked to arbitrary sites.
func (h *Handler) serveSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	cookie, err := r.Cookie("sso_session")
	if err != nil {
		writeSession(w, sessionResponse{Authenticated: false})
		return
	}

	userID, err := h.redis.GetSSOSession(r.Context(), cookie.Value)
	if err != nil {
		writeSession(w, sessionResponse{Authenticated: false})
		return
	}

	user, err := h.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeSession(w, sessionResponse{Authenticated: false})
		return
	}

	writeSession(w, sessionResponse{
		Authenticated: true,
		Email:         user.Email,
		Name:          strings.TrimSpace(user.FirstName + " " + user.LastName),
	})
}

func writeSession(w http.ResponseWriter, resp sessionResponse) {
	_ = json.NewEncoder(w).Encode(resp)
}

//go:embed templates/bridge.html
var bridgeTemplate string
var bridgeTmpl = template.Must(template.New("bridge").Parse(bridgeTemplate))

// serveBridge renders the iframe page that relays the session to the embedding
// app. The parent origin (?origin=) is validated against the redirect-URI
// origins of the requesting client (?client_id=), so the page never postMessages
// session state to an origin that client never registered.
func (h *Handler) serveBridge(w http.ResponseWriter, r *http.Request) {
	parentOrigin := r.URL.Query().Get("origin")
	clientID := r.URL.Query().Get("client_id")

	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil || !origins.Allows(client.RedirectURIs, parentOrigin) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	// Only this client's registered origin may frame the page.
	w.Header().Set("Content-Security-Policy", "frame-ancestors "+parentOrigin)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	originJSON, _ := json.Marshal(parentOrigin)
	_ = bridgeTmpl.Execute(w, map[string]template.JS{
		"ParentOriginJSON": template.JS(originJSON),
	})
}

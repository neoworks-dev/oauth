// Package google links a neoworks account to a Google account and holds the
// coordination state the client-side calendar sync needs.
//
// It lives on the oauth origin, not in apps/api, for two reasons. The Vault
// frame is served from this origin, so its calls here are same-origin — no CORS
// preflight and nothing to add to a future connect-src. And the Google
// client_secret belongs next to the rest of the OAuth machinery: Google issues
// refresh tokens only to a client that presents one, and only a Web-application
// client may name a hosted redirect URI, so a browser cannot complete this flow
// on its own.
//
// What this server learns is deliberately bounded. It holds the Google
// credential and an opaque uid → event-id map with a content hash; it never sees
// event content, because the sync loop runs inside the Vault and writes to
// neoworks encrypted.
package google

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/oauth/middleware/sso"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// LinkScope gates every route in this package. Without it these would be an open
// Google OAuth proxy for anyone holding any neoworks access token.
const LinkScope = "google:link"

// clientStore resolves the embedding client's registered record, whose redirect
// URIs decide which origins the callback window may post its result to.
type clientStore interface {
	GetClient(ctx context.Context, id string) (*oauth.Client, error)
}

// googleStore is the slice of the database this package owns.
type googleStore interface {
	LinkAccount(ctx context.Context, user models.RecordID, p database.LinkGoogleAccountParams) error
	Account(ctx context.Context, user models.RecordID) (*database.GoogleAccount, error)
	SetAccessToken(ctx context.Context, user models.RecordID, token string, expiresAt time.Time) error
	Unlink(ctx context.Context, user models.RecordID) error
	CalendarLinks(ctx context.Context, user models.RecordID) ([]database.GoogleCalendarLink, error)
	SaveCalendarLink(ctx context.Context, user models.RecordID, p database.SaveGoogleCalendarLinkParams) error
	DeleteCalendarLink(ctx context.Context, user models.RecordID, googleCalendarID string) error
	EventLinks(ctx context.Context, user models.RecordID, googleCalendarID string) ([]database.GoogleEventLink, error)
	SaveEventLinks(ctx context.Context, user models.RecordID, links []database.GoogleEventLink) error
	DeleteEventLink(ctx context.Context, user models.RecordID, uid string) error
}

// Sessions resolves the neoworks user behind a first-party browser session on
// this origin. The consent popup is a top-level navigation, so it carries the
// sso_session cookie rather than a bearer token.
type Sessions interface {
	UserID(r *http.Request) (string, error)
}

type redisSessions struct {
	redis *cache.RedisStore
}

// NewRedisSessions resolves sessions from the sso_session cookie set by
// /auth/login and /auth/signup.
func NewRedisSessions(redis *cache.RedisStore) Sessions {
	return redisSessions{redis: redis}
}

func (s redisSessions) UserID(r *http.Request) (string, error) {
	claims, err := sso.ResolveClaims(s.redis, r)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// Config is the registered Google Web-application client plus the endpoints to
// reach it. The endpoint fields exist so tests can point the whole flow at an
// httptest server; production leaves them empty and takes the defaults.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string

	AuthURL   string
	TokenURL  string
	RevokeURL string
	APIBase   string
}

const (
	defaultAuthURL   = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultTokenURL  = "https://oauth2.googleapis.com/token"
	defaultRevokeURL = "https://oauth2.googleapis.com/revoke"
	defaultAPIBase   = "https://www.googleapis.com"
)

// CalendarScope is Google's read/write calendar scope. It is a *sensitive*
// scope: until the app passes Google verification, consent is capped at 100
// users behind a warning screen.
const CalendarScope = "https://www.googleapis.com/auth/calendar"

// ConfigFromEnv reads the Google client registration. RedirectURI defaults to
// this origin's callback, which is what must be registered in Google Cloud.
func ConfigFromEnv() Config {
	return Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURI:  env("GOOGLE_REDIRECT_URI", config.ServiceURL("oauth")+"/google/callback"),
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// Enabled reports whether a Google client is registered. Without one the routes
// still mount but answer 503, so a deployment that has not set the secret fails
// visibly rather than redirecting users into a broken consent screen.
func (c Config) Enabled() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

func (c Config) authURL() string   { return orDefault(c.AuthURL, defaultAuthURL) }
func (c Config) tokenURL() string  { return orDefault(c.TokenURL, defaultTokenURL) }
func (c Config) revokeURL() string { return orDefault(c.RevokeURL, defaultRevokeURL) }
func (c Config) apiBase() string   { return orDefault(c.APIBase, defaultAPIBase) }

func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

type Handler struct {
	clients  clientStore
	google   googleStore
	sessions Sessions
	config   Config
	http     *http.Client
}

func NewHandler(clients clientStore, google googleStore, sessions Sessions, cfg Config) *Handler {
	return &Handler{
		clients:  clients,
		google:   google,
		sessions: sessions,
		config:   cfg,
		http:     &http.Client{Timeout: 20 * time.Second},
	}
}

// Register mounts the consent flow. Both routes are top-level browser
// navigations authenticated by the sso_session cookie — a popup cannot carry a
// bearer token.
func (h *Handler) Register(r chi.Router) {
	r.Get("/google/connect", h.connect)
	r.Get("/google/callback", h.callback)
}

// RegisterAuthenticated mounts the routes the Vault calls with the embedding
// app's access token. The caller supplies the bearer middleware; each handler
// additionally checks the google:link scope, because the middleware only proves
// the token is valid, not that this capability was granted.
func (h *Handler) RegisterAuthenticated(r chi.Router) {
	r.Get("/google/link", h.linkStatus)
	r.Delete("/google/link", h.unlink)
	r.Get("/google/token", h.accessToken)
	r.Get("/google/calendars", h.listCalendars)
	r.Get("/google/calendar-links", h.listCalendarLinks)
	r.Put("/google/calendar-links", h.saveCalendarLink)
	r.Delete("/google/calendar-links", h.deleteCalendarLink)
	r.Get("/google/event-links", h.listEventLinks)
	r.Put("/google/event-links", h.saveEventLinks)
	r.Delete("/google/event-links", h.deleteEventLink)
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// caller authenticates a Vault-side request: a valid bearer token that carries
// google:link. Anything less gets no user back and the response is already
// written.
func caller(w http.ResponseWriter, r *http.Request) (models.RecordID, bool) {
	claim := middleware.ClaimFromContext(r.Context())
	if claim == nil {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return models.RecordID{}, false
	}
	if !hasScope(claim, LinkScope) {
		jsonErr(w, "scope_not_granted", http.StatusForbidden)
		return models.RecordID{}, false
	}
	return models.NewRecordID("user", claim.Subject), true
}

func hasScope(claim *oauth.Claims, scope string) bool {
	for _, granted := range claim.Scope {
		if granted == scope {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func jsonErr(w http.ResponseWriter, message string, status int) {
	writeJSON(w, status, map[string]string{"error": message})
}

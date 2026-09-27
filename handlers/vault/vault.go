// Package vault serves the cross-origin crypto sandbox embedded by client apps
// (e.g. contacts). The page holds the user's AMK and answers encrypt/decrypt over
// postMessage; the AMK never crosses the origin boundary into the embedding app.
//
// It embraces browser storage partitioning: the vault keeps ITS OWN device
// keypair in its own (partitioned, per embedder) IndexedDB. Calls to the
// authenticated keys API carry the embedding client's access token as a bearer
// credential, so no first-party session of its own is needed.
//
// Any origin may frame it. The embedder's token decides what it can decrypt —
// see serveVault.
package vault

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/oauth/handlers/origins"
)

//go:embed templates/vault.html
var vaultTemplate string
var vaultTmpl = template.Must(template.New("vault").Parse(vaultTemplate))

//go:embed templates/vault-unlock.html
var vaultUnlockTemplate string
var vaultUnlockTmpl = template.Must(template.New("vault-unlock").Parse(vaultUnlockTemplate))

// store is the slice of the database this package needs: the embedding client's
// registered record, for its display name and its redirect URIs.
type store interface {
	GetClient(ctx context.Context, id string) (*oauth.Client, error)
}

type Handler struct {
	store store
}

func NewHandler(store store) *Handler {
	return &Handler{store: store}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/vault", h.serveVault)
	r.Get("/vault/unlock", h.serveVaultUnlock)
}

type vaultData struct {
	AppName string
	// APIURLJSON is the JSON-quoted API origin. The vault syncs E2EE collections
	// (contacts) itself, so the decrypted store never leaves this origin.
	APIURLJSON template.JS
}

// apiURL is the API origin the vault fetches for E2EE collection sync.
func apiURL() string {
	if v := os.Getenv("API_URL"); v != "" {
		return v
	}
	return config.ServiceURL("api")
}

// lookupClient resolves the embedding client's registered record. An absent or
// unknown client_id yields nil; callers treat that as no name and no registered
// origins rather than failing the render.
func (h *Handler) lookupClient(ctx context.Context, clientID string) *oauth.Client {
	if clientID == "" {
		return nil
	}
	client, err := h.store.GetClient(ctx, clientID)
	if err != nil {
		return nil
	}
	return client
}

// appNameOf is the embedding client's display name, taken from its registered
// record (authoritative — never from caller-supplied text).
func appNameOf(client *oauth.Client, clientID string) string {
	if client != nil && client.Name != nil && *client.Name != "" {
		return *client.Name
	}
	if clientID == "" {
		return "This app"
	}
	return clientID
}

func (h *Handler) serveVault(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	apiJSON, _ := json.Marshal(apiURL())

	var buf bytes.Buffer
	if err := vaultTmpl.Execute(&buf, vaultData{
		AppName:    appNameOf(h.lookupClient(r.Context(), clientID), clientID),
		APIURLJSON: template.JS(apiJSON),
	}); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}

	// Framable by anyone on purpose. The frame renders nothing and its
	// capability comes from the embedder's access token, not its origin: the
	// granted scopes are resolved by introspecting that token against this
	// server, and a scope's data can only be decrypted by the keypair derived
	// for it. An embedder without a token holding the scope gets no key, so the
	// origin it framed from decides nothing.
	w.Header().Set("Content-Security-Policy", "frame-ancestors *")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// vaultUnlockData is the passphrase window's template input. OAuthHost is shown
// in the copy so the address bar has something to be checked against.
// AllowedOriginsJSON gates who may name the key the account key is sealed to —
// see unlockOrigins.
type vaultUnlockData struct {
	AllowedOriginsJSON template.JS
	APIURLJSON         template.JS
	AppName            string
	AppNameJSON        template.JS
	OAuthHost          string
}

// unlockOrigins are the origins this window accepts a `vault-unlock-init` from.
// Unlike the vault frame, this gate is load-bearing: the message names the
// public key the account master key is sealed to, so an origin that can send it
// gets that key sealed to a keypair it chose. The client's own registered
// redirect URIs are the right source — an app may drive the unlock from exactly
// the origins it already registered to receive sign-ins — and it is what
// login.html gates the same message on.
func unlockOrigins(client *oauth.Client) []string {
	if client == nil {
		return []string{}
	}
	return origins.FromRedirectURIs(client.RedirectURIs)
}

// serveVaultUnlock renders the window where the user types their password. It is
// a top-level document on purpose: the vault frame has no address bar, so an
// embedding app could draw a convincing copy of a prompt inside it. Here the
// browser's own chrome states the origin, and `frame-ancestors 'none'` keeps the
// page from being framed into a lookalike.
func (h *Handler) serveVaultUnlock(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	client := h.lookupClient(r.Context(), clientID)
	originsJSON, _ := json.Marshal(unlockOrigins(client))
	apiJSON, _ := json.Marshal(apiURL())
	appName := appNameOf(client, clientID)
	appNameJSON, _ := json.Marshal(appName)

	var buf bytes.Buffer
	if err := vaultUnlockTmpl.Execute(&buf, vaultUnlockData{
		AllowedOriginsJSON: template.JS(originsJSON),
		APIURLJSON:         template.JS(apiJSON),
		AppName:            appName,
		AppNameJSON:        template.JS(appNameJSON),
		OAuthHost:          r.Host,
	}); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

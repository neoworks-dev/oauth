// Package vault serves the cross-origin crypto sandbox embedded by client apps
// (e.g. muse). The page holds the user's AMK and answers encrypt/decrypt over
// postMessage; the AMK never crosses the origin boundary into the embedding app.
//
// It embraces browser storage partitioning: the vault keeps ITS OWN device
// keypair in its own (partitioned, per embedder) IndexedDB, and uses the
// Storage Access API only to obtain first-party cookies so it can reach the
// authenticated keys API.
package vault

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/storage/database"
)

//go:embed templates/vault.html
var vaultTemplate string
var vaultTmpl = template.Must(template.New("vault").Parse(vaultTemplate))

type Handler struct {
	store          *database.SurrealStore
	allowedOrigins []string
}

func NewHandler(store *database.SurrealStore) *Handler {
	raw := os.Getenv("VAULT_ALLOWED_ORIGINS")
	if raw == "" {
		return &Handler{store: store, allowedOrigins: defaultAllowedOrigins()}
	}
	return &Handler{store: store, allowedOrigins: strings.Fields(raw)}
}

// defaultAllowedOrigins derives the embedding-app origins from the base domain
// (dev: neoworks.localhost, prod: neoworks.dev). Every app that embeds the Vault
// iframe gets its `{app}.{base}` origin; the packaged Electron chat app runs
// under a custom protocol instead of a domain.
func defaultAllowedOrigins() []string {
	apps := []string{"muse", "contacts", "photos", "chat", "chat-desktop"}
	origins := make([]string, 0, len(apps)+1)
	for _, app := range apps {
		origins = append(origins, config.ServiceURL(app))
	}
	origins = append(origins, "app://chat")
	return origins
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/vault", h.serveVault)
}

type vaultData struct {
	AllowedOriginsJSON template.JS
	AppName            string
}

// appName resolves the embedding client's display name from its registered
// record (authoritative — never from caller-supplied text).
func (h *Handler) appName(r *http.Request) string {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		return "This app"
	}
	if client, err := h.store.GetClient(r.Context(), clientID); err == nil &&
		client.Name != nil && *client.Name != "" {
		return *client.Name
	}
	return clientID
}

func (h *Handler) serveVault(w http.ResponseWriter, r *http.Request) {
	originsJSON, _ := json.Marshal(h.allowedOrigins)

	var buf bytes.Buffer
	if err := vaultTmpl.Execute(&buf, vaultData{
		AllowedOriginsJSON: template.JS(originsJSON),
		AppName:            h.appName(r),
	}); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}

	// Allow framing only by the configured client origins.
	w.Header().Set("Content-Security-Policy", "frame-ancestors "+strings.Join(h.allowedOrigins, " "))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

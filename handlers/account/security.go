package account

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/oauth/middleware/sso"
)

//go:embed templates/security.html
var securityTemplate string
var securityTmpl = template.Must(template.New("security").Parse(securityTemplate))

type SecurityHandler struct {
	store *database.SurrealStore
	redis *cache.RedisStore
}

func NewSecurityHandler(store *database.SurrealStore, redis *cache.RedisStore) *SecurityHandler {
	return &SecurityHandler{store: store, redis: redis}
}

func (handler *SecurityHandler) Register(r chi.Router) {
	r.Get("/account/security", handler.serveSecurity)
}

type securityData struct {
	Email string
}

// serveSecurity renders the device/recovery management page. It requires an
// sso_session cookie — anonymous visitors are sent back to apps/web, which
// owns the login UI.
func (handler *SecurityHandler) serveSecurity(w http.ResponseWriter, r *http.Request) {
	claims, err := sso.ResolveClaims(handler.redis, r)
	if err != nil {
		http.Redirect(w, r, config.ServiceURL("")+"/dashboard", http.StatusFound)
		return
	}

	user, err := handler.store.GetUserByID(r.Context(), claims.Subject)
	if err != nil {
		http.Redirect(w, r, config.ServiceURL("")+"/dashboard", http.StatusFound)
		return
	}

	var buf bytes.Buffer
	if err := securityTmpl.Execute(&buf, securityData{Email: user.Email}); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

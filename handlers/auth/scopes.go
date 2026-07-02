package auth

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/shared"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
)

//go:embed templates/scopes.html
var scopesTemplate string
var scopesTmpl = template.Must(template.New("scopes").Parse(scopesTemplate))

type scopeView struct {
	Name        string
	Description string
}

// scopeCatalog holds curated copy for scopes that don't follow the
// [organization:]entity:action shape (the standard OIDC scopes) or that
// need friendlier wording than the parser below would produce on its own.
var scopeCatalog = map[string]scopeView{
	"openid":  {Name: "Verify your identity"},
	"profile": {Name: "Access your profile", Description: "Your name, username, and avatar"},
	"email":   {Name: "Access your email address"},
	"offline": {Name: "Stay signed in", Description: "Maintain access while you're not using the app"},
	// Encryption scopes gate end-to-end decryption: granting one lets the app
	// decrypt that category of your data and nothing else.
	"photos:read":  {Name: "View your photos", Description: "Decrypt and display your photo library"},
	"photos:write": {Name: "Add and edit photos", Description: "Encrypt and store new photos for you"},
	"legacy:read":  {Name: "Read your existing encrypted data", Description: "Data created before per-app encryption scopes"},
}

// actionVerbs maps the action segment of a scope to the verb used in its label.
var actionVerbs = map[string]string{
	"read":   "View",
	"write":  "Edit",
	"create": "Create",
	"delete": "Delete",
	"admin":  "Manage",
	"*":      "Full access to",
}

// describeScope turns a raw scope string into a human-readable name and
// description. Scopes follow "[organization:]entity:action" — organization
// is optional, so a scope is either "entity:action" or "org:entity:action".
// Known scopes are taken from scopeCatalog; everything else is derived from
// its parts so unknown scopes never render blank.
func describeScope(scope string) scopeView {
	if v, ok := scopeCatalog[scope]; ok {
		return v
	}

	parts := strings.Split(scope, ":")

	var org, entity, action string
	switch len(parts) {
	case 2:
		entity, action = parts[0], parts[1]
	case 3:
		org, entity, action = parts[0], parts[1], parts[2]
	default:
		return scopeView{Name: scope}
	}

	verb, ok := actionVerbs[action]
	if !ok {
		verb = capitalize(action)
	}

	view := scopeView{Name: verb + " " + strings.ReplaceAll(entity, "_", " ")}
	if org != "" {
		view.Description = "Limited to the " + org + " organization"
	}
	return view
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func buildScopeViews(scopes []string) []scopeView {
	views := make([]scopeView, 0, len(scopes))
	for _, s := range scopes {
		views = append(views, describeScope(s))
	}
	return views
}

func NewScopesHandler(redis *cache.RedisStore, store *database.SurrealStore, loginURL string) *ScopesHandler {
	return &ScopesHandler{
		redis:    redis,
		store:    store,
		loginURL: loginURL,
	}
}

type ScopesHandler struct {
	redis    *cache.RedisStore
	store    *database.SurrealStore
	loginURL string
}

func (handler *ScopesHandler) Register(router chi.Router) {
	router.Get("/auth/scopes", handler.serveScopes)
}

func (handler *ScopesHandler) serveScopes(response http.ResponseWriter, request *http.Request) {
	loginChallengeID := request.URL.Query().Get("login_challenge")
	if loginChallengeID == "" {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	challenge, err := handler.redis.GetLoginChallenge(request.Context(), loginChallengeID)
	if err != nil {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	client, err := handler.store.GetClient(request.Context(), challenge.ClientID)
	if err != nil {
		http.Error(response, "Invalid client", http.StatusBadRequest)
		return
	}

	data := struct {
		LoginChallenge string
		AppName        string
		Scopes         []scopeView
	}{
		LoginChallenge: loginChallengeID,
		AppName:        client.ID.ID.(string),
		Scopes:         buildScopeViews(challenge.Scopes),
	}

	var buf bytes.Buffer
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		http.Error(response, "Failed to render template", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(response)
}

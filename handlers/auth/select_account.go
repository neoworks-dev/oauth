package auth

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
)

const selectAccountTTL = 30 * 24 * time.Hour

// SelectAccountHandler lets a returning device pick which of its signed-in
// accounts to continue with, instead of silently using the most recent one.
type SelectAccountHandler struct {
	redis    *cache.RedisStore
	store    *database.SurrealStore
	issuer   *oauth.TokenIssuer
	loginURL string
}

func NewSelectAccountHandler(redis *cache.RedisStore, store *database.SurrealStore, issuer *oauth.TokenIssuer, loginURL string) *SelectAccountHandler {
	return &SelectAccountHandler{redis: redis, store: store, issuer: issuer, loginURL: loginURL}
}

func (handler *SelectAccountHandler) Register(router chi.Router) {
	router.Get("/auth/select-account", handler.serve)
	router.Post("/auth/select-account", handler.choose)
}

//go:embed templates/select_account.html
var selectAccountTemplate string
var selectAccountTmpl = template.Must(template.New("select_account").Parse(selectAccountTemplate))

type accountView struct {
	UserID  string
	Email   string
	Name    string
	Initial string
}

func (handler *SelectAccountHandler) serve(response http.ResponseWriter, request *http.Request) {
	challengeKey := request.URL.Query().Get("login_challenge")
	if challengeKey == "" {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	challenge, err := handler.redis.GetLoginChallenge(request.Context(), challengeKey)
	if err != nil || challenge == nil {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	client, err := handler.store.GetClient(request.Context(), challenge.ClientID)
	if err != nil {
		http.Error(response, "Invalid client", http.StatusBadRequest)
		return
	}

	accounts := handler.resolveAccounts(request)
	// No live accounts on this device — fall back to the credential form.
	if len(accounts) == 0 {
		redirectToLogin(response, request, challengeKey)
		return
	}

	data := struct {
		LoginChallenge string
		AppName        string
		Accounts       []accountView
	}{
		LoginChallenge: challengeKey,
		AppName:        client.ID.ID.(string),
		Accounts:       accounts,
	}

	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := selectAccountTmpl.Execute(response, data); err != nil {
		http.Error(response, "Failed to render template", http.StatusInternalServerError)
	}
}

func (handler *SelectAccountHandler) choose(response http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(response, "Invalid form data", http.StatusBadRequest)
		return
	}

	challengeKey := request.FormValue("login_challenge")
	if request.FormValue("action") == "add" {
		redirectToAddAccount(response, request, challengeKey)
		return
	}

	selectedUserID := request.FormValue("user_id")
	ssoSession, err := request.Cookie("sso_session")
	if err != nil {
		redirectToLogin(response, request, challengeKey)
		return
	}

	// Only an account already in this device's session may be selected, so a
	// forged user_id cannot activate an account the device never signed into.
	if err := handler.redis.SetActiveSSOAccount(request.Context(), ssoSession.Value, selectedUserID, selectAccountTTL); err != nil {
		redirectToSelectAccount(response, request, challengeKey)
		return
	}

	challenge, err := handler.redis.GetLoginChallenge(request.Context(), challengeKey)
	if err != nil || challenge == nil {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	user, err := handler.store.GetUserByID(request.Context(), selectedUserID)
	if err != nil {
		redirectToSelectAccount(response, request, challengeKey)
		return
	}

	shared.HandleConsentRedirect(handler.redis, handler.store, handler.issuer, user, challenge, response, request)
}

// resolveAccounts loads the user record for every account in the device's
// session, skipping any that no longer resolve.
func (handler *SelectAccountHandler) resolveAccounts(request *http.Request) []accountView {
	ssoSession, err := request.Cookie("sso_session")
	if err != nil {
		return nil
	}

	userIDs, err := handler.redis.GetSSOAccounts(request.Context(), ssoSession.Value)
	if err != nil {
		return nil
	}

	views := make([]accountView, 0, len(userIDs))
	for _, userID := range userIDs {
		user, err := handler.store.GetUserByID(request.Context(), userID)
		if err != nil {
			continue
		}
		views = append(views, accountView{
			UserID:  userID,
			Email:   user.Email,
			Name:    strings.TrimSpace(user.FirstName + " " + user.LastName),
			Initial: userInitial(user.Email),
		})
	}
	return views
}

func userInitial(email string) string {
	if email == "" {
		return "?"
	}
	return strings.ToUpper(email[:1])
}

func redirectToLogin(response http.ResponseWriter, request *http.Request, challengeKey string) {
	http.Redirect(response, request, "/auth/login?login_challenge="+url.QueryEscape(challengeKey), http.StatusSeeOther)
}

func redirectToAddAccount(response http.ResponseWriter, request *http.Request, challengeKey string) {
	target := url.URL{Path: "/auth/login"}
	query := target.Query()
	query.Set("login_challenge", challengeKey)
	query.Set("add", "1")
	target.RawQuery = query.Encode()
	http.Redirect(response, request, target.String(), http.StatusSeeOther)
}

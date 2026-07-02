package auth

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/shared"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// signinQRDataURI renders the QR a trusted device scans in the authenticator to
// approve this sign-in. It encodes only the login_challenge (no secrets) behind
// the neoauth:// scheme the app already parses for pairing. Returns "" on
// failure so the page simply omits the QR rather than erroring.
//
// The result is typed template.URL because html/template otherwise rejects a
// data: URI in a src attribute and replaces it with "#ZgotmplZ". This is safe:
// the value is a self-generated PNG data URI, never user input.
func signinQRDataURI(loginChallenge string) template.URL {
	target := url.URL{Scheme: "neoauth", Host: "signin"}
	query := target.Query()
	query.Set("lc", loginChallenge)
	target.RawQuery = query.Encode()

	png, err := qrcode.Encode(target.String(), qrcode.Medium, 220)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}

func NewLoginHandler(redis *cache.RedisStore, store *database.SurrealStore, issuer *oauth.TokenIssuer, loginURL string) *LoginHandler {
	return &LoginHandler{
		redis:    redis,
		store:    store,
		issuer:   issuer,
		loginURL: loginURL,
	}
}

type LoginHandler struct {
	redis    *cache.RedisStore
	store    *database.SurrealStore
	issuer   *oauth.TokenIssuer
	loginURL string
}

func (handler *LoginHandler) Register(router chi.Router) {
	router.Post("/auth/login", handler.handleLogin)
	router.Get("/auth/login", handler.serveLogin)
}

func (handler *LoginHandler) handleLogin(response http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(response, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := request.FormValue("email")
	password := request.FormValue("password")
	challengeKey := request.FormValue("login_challenge")

	// Validate credentials. On failure, bounce back to the rendered login page
	// with an error code instead of returning bare text. The message stays
	// identical whether the email is unknown or the password is wrong, so we
	// never reveal which accounts exist.
	user, err := handler.store.GetUserByEmail(request.Context(), email)
	if err != nil {
		redirectToLoginWithError(response, request, challengeKey, "invalid_credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		redirectToLoginWithError(response, request, challengeKey, "invalid_credentials")
		return
	}
	// The user is logged in. Add the account to the device's SSO session
	// (creating one if absent) so one device can hold several accounts.
	if err := shared.EstablishSSOSession(handler.redis, response, request, user.ID.ID.(string)); err != nil {
		http.Error(response, "Failed to create session", http.StatusInternalServerError)
		return
	}

	challenge, err := handler.redis.GetLoginChallenge(request.Context(), challengeKey)
	if err != nil || challenge == nil {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	shared.HandleConsentRedirect(handler.redis, handler.store, handler.issuer, user, challenge, response, request)
}

// redirectToSelectAccount sends the user to the account picker, preserving the
// login challenge so the chosen account can complete the OAuth flow.
func redirectToSelectAccount(response http.ResponseWriter, request *http.Request, challengeKey string) {
	target := url.URL{Path: "/auth/select-account"}
	query := target.Query()
	query.Set("login_challenge", challengeKey)
	target.RawQuery = query.Encode()
	http.Redirect(response, request, target.String(), http.StatusSeeOther)
}

// clearSSOCookie drops a session that no longer resolves, both server-side and
// in the browser, so a stale cookie does not keep bouncing the user.
func clearSSOCookie(response http.ResponseWriter, redis *cache.RedisStore, ctx context.Context, token string) {
	_ = redis.DeleteSSOSession(ctx, token)
	http.SetCookie(response, &http.Cookie{
		Name:     "sso_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}

// redirectToLoginWithError bounces a failed POST back to the rendered login
// page (GET) so the user sees the form again with an inline error. The error is
// passed as a stable code, never reflected free text, to avoid reflecting
// attacker-controlled input into the page.
func redirectToLoginWithError(response http.ResponseWriter, request *http.Request, challengeKey, errorCode string) {
	target := url.URL{Path: "/auth/login"}
	query := target.Query()
	query.Set("login_challenge", challengeKey)
	query.Set("error", errorCode)
	target.RawQuery = query.Encode()

	http.Redirect(response, request, target.String(), http.StatusSeeOther)
}

// loginErrorMessage maps a known error code to a user-facing message. Unknown
// or empty codes yield an empty string so the error block stays hidden.
func loginErrorMessage(errorCode string) string {
	switch errorCode {
	case "invalid_credentials":
		return "Invalid email or password. Please try again."
	default:
		return ""
	}
}

//go:embed templates/login.html
var loginTemplate string
var loginTmpl = template.Must(template.New("login").Parse(loginTemplate))

func (handler *LoginHandler) serveLogin(response http.ResponseWriter, request *http.Request) {
	var buf bytes.Buffer

	challengeKey := request.URL.Query().Get("login_challenge")
	if challengeKey == "" {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	challenge, err := handler.redis.GetLoginChallenge(request.Context(), challengeKey)
	if err != nil {
		shared.RestartLogin(response, request, handler.loginURL)
		return
	}

	ctx := request.Context()
	client, err := handler.store.GetClient(ctx, challenge.ClientID)
	if err != nil {
		http.Error(response, "Invalid client", http.StatusBadRequest)
		return
	}

	// When the device already holds at least one account, send the user to the
	// account picker instead of signing them in directly. "?add=1" forces the
	// credential form so the user can add another account from the picker.
	if request.URL.Query().Get("add") != "1" {
		ssoSession, err := request.Cookie("sso_session")
		if err != nil && err != http.ErrNoCookie {
			http.Error(response, "Failed to read session cookie", http.StatusInternalServerError)
			return
		}
		if ssoSession != nil {
			accounts, err := handler.redis.GetSSOAccounts(request.Context(), ssoSession.Value)
			if err != nil {
				clearSSOCookie(response, handler.redis, request.Context(), ssoSession.Value)
			} else if len(accounts) > 0 {
				redirectToSelectAccount(response, request, challengeKey)
				return
			}
		}
	}

	var notice string
	if request.URL.Query().Get("reset") == "success" {
		notice = "Password reset. Please sign in with your new password."
	}

	data := struct {
		LoginChallenge string
		AppName        string
		Error          string
		Notice         string
		SigninQR       template.URL
	}{
		LoginChallenge: challengeKey,
		AppName:        client.ID.ID.(string),
		Error:          loginErrorMessage(request.URL.Query().Get("error")),
		Notice:         notice,
		SigninQR:       signinQRDataURI(challengeKey),
	}

	if err := loginTmpl.Execute(&buf, data); err != nil {
		http.Error(response, "Failed to render template", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = buf.WriteTo(response)
	if err != nil {
		http.Error(response, "Failed to write response", http.StatusInternalServerError)
	}
}

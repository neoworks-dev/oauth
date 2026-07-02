package oauth

import (
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

type AuthorizeHandler struct {
	clients  *database.SurrealStore
	codes    *cache.RedisStore
	loginURL string
}

func NewAuthorizeHandler(clients *database.SurrealStore, codes *cache.RedisStore, loginURL string) *AuthorizeHandler {
	return &AuthorizeHandler{clients: clients, codes: codes, loginURL: loginURL}
}

func (h *AuthorizeHandler) Register(r chi.Router) {
	r.Get("/oauth/authorize", h.handleAuthorize)
}

func (h *AuthorizeHandler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	responseType := query.Get("response_type")
	scope := query.Get("scope")
	state := query.Get("state")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	// Validate client_id and redirect_uri first — redirect_uri is untrusted
	// until the client is validated, so no RedirectError before this point.
	if clientID == "" {
		RedirectToErrorPage(w, r, "invalid_request", "This sign-in link is missing the application's identifier (client_id), so we can't tell who is requesting access. The link is likely broken or incomplete — go back to the application and start sign-in again.")
		return
	}
	if redirectURI == "" {
		RedirectToErrorPage(w, r, "invalid_request", "This sign-in link is missing the return address (redirect_uri) the application uses to receive the result. The link looks malformed — go back to the application and start sign-in again.")
		return
	}

	client, err := h.clients.GetClient(ctx, clientID)
	if err != nil {
		RedirectToErrorPage(w, r, "unauthorized_client", "The application requesting access isn't recognized by NeoWorks. It may not be registered, or this link may have been altered. For your safety, don't enter your credentials — contact the application's provider if you reached this from a link you trust.")
		return
	}
	if !shared.ContainsURI(client.RedirectURIs, redirectURI) {
		// redirect_uri mismatch is a classic phishing / open-redirect vector:
		// an attacker reuses a valid client_id but swaps the return address to
		// capture the authorization code. Stop here and warn the user explicitly.
		RedirectToErrorPage(w, r, "invalid_request", "The address this application asked us to return you to isn't one it has registered with NeoWorks. This often means the link was tampered with to send you (and your sign-in) somewhere unsafe. We've blocked the request to protect your account — do not continue.")
		return
	}

	// redirect_uri is now trusted — safe to use it in error redirects below.
	// These bounce back to the registered application, so descriptions stay
	// concise and developer-facing rather than carrying user security warnings.
	if responseType != "code" {
		shared.RedirectError(w, r, redirectURI, state, "unsupported_response_type", "Only the authorization code flow is supported. Set response_type=code.")
		return
	}
	// Public clients must use PKCE; confidential clients (those with a secret)
	// authenticate the token exchange with client_secret instead.
	confidential := !client.Public && client.SecretHash != ""
	if !confidential {
		if codeChallenge == "" {
			shared.RedirectError(w, r, redirectURI, state, "invalid_request", "A PKCE code_challenge is required for this client.")
			return
		}
		if codeChallengeMethod != "S256" {
			shared.RedirectError(w, r, redirectURI, state, "invalid_request", "Unsupported code_challenge_method — only S256 is accepted.")
			return
		}
	}
	if !shared.ScopesAllowed(client.Scopes, strings.Fields(scope)) {
		shared.RedirectError(w, r, redirectURI, state, "invalid_scope", "The request asked for one or more permissions this application isn't allowed to use.")
		return
	}

	challenge := oauth.LoginChallenge{
		ID:                  shared.GenerateID(),
		ClientID:            clientID,
		Scopes:              strings.Fields(scope),
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := h.codes.SaveLoginChallenge(ctx, challenge); err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	// Safely construct the login URL to prevent query injection.
	redirectURL := &url.URL{
		Scheme: "http",
		Host:   r.Host,
		Path:   "/auth/login",
	}

	q := redirectURL.Query()
	q.Set("login_challenge", challenge.ID)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

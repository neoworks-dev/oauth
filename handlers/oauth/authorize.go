package oauth

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"crypto/rand"
	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/scopes"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/wire"
)

const loginChallengeTTL = 10 * time.Minute

// ChallengeSaver persists validated authorization requests.
type ChallengeSaver interface {
	SaveLoginChallenge(ctx context.Context, challenge cache.LoginChallenge) error
}

type AuthorizeHandler struct {
	clients   Store
	challenge ChallengeSaver
	vaultURL  string
}

func NewAuthorizeHandler(clients Store, challenges ChallengeSaver, vaultURL string) *AuthorizeHandler {
	return &AuthorizeHandler{clients: clients, challenge: challenges, vaultURL: strings.TrimRight(vaultURL, "/")}
}

func (handler *AuthorizeHandler) Register(router chi.Router) {
	router.Get("/oauth/authorize", handler.handleAuthorize)
}

func (handler *AuthorizeHandler) handleAuthorize(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	client, ok := handler.trustedClient(response, request)
	if !ok {
		return
	}
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")
	requestedScopes := strings.Fields(query.Get("scope"))

	if query.Get("response_type") != "code" {
		redirectError(response, request, redirectURI, state, "unsupported_response_type", "Only response_type=code is supported.")
		return
	}
	if query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		redirectError(response, request, redirectURI, state, "invalid_request", "PKCE with code_challenge_method=S256 is required.")
		return
	}
	if !scopes.AllKnown(requestedScopes) || !scopes.Subset(client.Scopes, requestedScopes) {
		redirectError(response, request, redirectURI, state, "invalid_scope", "The request asked for scopes this application may not use.")
		return
	}
	install, err := parseInstallRequest(query.Get("install_id"), query.Get("install_enc_pub"),
		query.Get("install_sign_pub"), query.Get("install_name"))
	if err != nil {
		redirectError(response, request, redirectURI, state, "invalid_request", err.Error())
		return
	}
	if install == nil && scopes.WantsCollections(requestedScopes) {
		redirectError(response, request, redirectURI, state, "invalid_request", "Data scopes require install_id, install_enc_pub and install_sign_pub.")
		return
	}
	handler.startLogin(response, request, cache.LoginChallenge{
		ID:                  newChallengeID(),
		ClientID:            client.ID,
		Scopes:              requestedScopes,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: "S256",
		Install:             install,
		ExpiresAt:           time.Now().Add(loginChallengeTTL),
	})
}

// trustedClient resolves the client and checks the redirect URI. Until both
// pass, errors go to the local error page and never to the redirect URI.
func (handler *AuthorizeHandler) trustedClient(response http.ResponseWriter, request *http.Request) (*store.Client, bool) {
	query := request.URL.Query()
	if query.Get("client_id") == "" {
		RedirectToErrorPage(response, request, "invalid_request", "The sign-in link is missing the application identifier (client_id). Go back to the application and start again.")
		return nil, false
	}
	if query.Get("redirect_uri") == "" {
		RedirectToErrorPage(response, request, "invalid_request", "The sign-in link is missing the return address (redirect_uri). Go back to the application and start again.")
		return nil, false
	}
	client, err := handler.clients.GetClient(request.Context(), query.Get("client_id"))
	if err != nil {
		RedirectToErrorPage(response, request, "unauthorized_client", "This application is not registered with Neoworks. Do not enter your credentials.")
		return nil, false
	}
	if !slices.Contains(client.RedirectURIs, query.Get("redirect_uri")) {
		RedirectToErrorPage(response, request, "invalid_request", "This application asked to send you to an address it has not registered. The request was blocked.")
		return nil, false
	}
	return client, true
}

func (handler *AuthorizeHandler) startLogin(response http.ResponseWriter, request *http.Request, challenge cache.LoginChallenge) {
	err := handler.challenge.SaveLoginChallenge(request.Context(), challenge)
	if err != nil {
		http.Error(response, "server_error", http.StatusInternalServerError)
		return
	}
	target := url.URL{Path: "/signin"}
	values := url.Values{"login_challenge": {challenge.ID}}
	target.RawQuery = values.Encode()
	http.Redirect(response, request, handler.vaultURL+target.String(), http.StatusFound)
}

func newChallengeID() string {
	identifier := make([]byte, 16)
	_, _ = rand.Read(identifier)
	return wire.EncodeBase64URL(identifier)
}

func redirectError(response http.ResponseWriter, request *http.Request, redirectURI, state, code, description string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(response, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	values := target.Query()
	values.Set("error", code)
	if state != "" {
		values.Set("state", state)
	}
	values.Set("error_description", description)
	target.RawQuery = values.Encode()
	http.Redirect(response, request, target.String(), http.StatusFound)
}

package oauth

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/tokens"
	"golang.org/x/crypto/bcrypt"
)

// TokenState is the Redis slice the token endpoint needs.
type TokenState interface {
	ConsumeAuthCode(ctx context.Context, code string) (*cache.AuthCode, error)
	AcquireRotationLock(ctx context.Context, tokenID string) error
	SaveRotationResult(ctx context.Context, tokenID string, result cache.RefreshResult, ttl time.Duration) error
	GetRotationResult(ctx context.Context, tokenID string) (*cache.RefreshResult, error)
}

type TokenHandler struct {
	state  TokenState
	store  Store
	issuer *tokens.Issuer
}

func NewTokenHandler(state TokenState, tokenStore Store, issuer *tokens.Issuer) *TokenHandler {
	return &TokenHandler{state: state, store: tokenStore, issuer: issuer}
}

func (handler *TokenHandler) Register(router chi.Router) {
	router.Post("/oauth/token", handler.handleToken)
}

func (handler *TokenHandler) handleToken(response http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		tokenError(response, "invalid_request", http.StatusBadRequest)
		return
	}
	switch request.FormValue("grant_type") {
	case "authorization_code":
		handler.handleAuthorizationCode(response, request)
	case "refresh_token":
		handler.handleRefresh(response, request)
	default:
		tokenError(response, "unsupported_grant_type", http.StatusBadRequest)
	}
}

func (handler *TokenHandler) handleAuthorizationCode(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	code := request.FormValue("code")
	redirectURI := request.FormValue("redirect_uri")
	if code == "" || redirectURI == "" {
		tokenError(response, "invalid_grant", http.StatusBadRequest)
		return
	}
	authCode, err := handler.state.ConsumeAuthCode(ctx, code)
	if err != nil || time.Now().After(authCode.ExpiresAt) || authCode.RedirectURI != redirectURI {
		tokenError(response, "invalid_grant", http.StatusBadRequest)
		return
	}
	if !handler.authenticateCodeExchange(response, request, authCode) {
		return
	}
	handler.issueFromCode(response, request, authCode)
}

// authenticateCodeExchange requires PKCE for every client and the client
// secret on top of it for confidential clients.
func (handler *TokenHandler) authenticateCodeExchange(response http.ResponseWriter, request *http.Request, authCode *cache.AuthCode) bool {
	ctx := request.Context()
	client, err := handler.store.GetClient(ctx, authCode.ClientID)
	if err != nil {
		tokenError(response, "invalid_client", http.StatusBadRequest)
		return false
	}
	err = tokens.VerifyPKCE(request.FormValue("code_verifier"), authCode.CodeChallenge, authCode.CodeChallengeMethod)
	if err != nil {
		slog.WarnContext(ctx, "pkce verification failed", "client_id", authCode.ClientID)
		tokenError(response, "invalid_grant", http.StatusBadRequest)
		return false
	}
	if client.IsConfidential() && !secretMatches(client, request) {
		tokenError(response, "invalid_client", http.StatusUnauthorized)
		return false
	}
	return true
}

func secretMatches(client *store.Client, request *http.Request) bool {
	secret := clientSecretFromRequest(request)
	if secret == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) == nil
}

func (handler *TokenHandler) issueFromCode(response http.ResponseWriter, request *http.Request, authCode *cache.AuthCode) {
	ctx := request.Context()
	accessToken, _, err := handler.issuer.IssueAccessToken(tokens.AccessTokenParams{
		UserID:    authCode.UserID,
		ClientID:  authCode.ClientID,
		Scopes:    authCode.Scopes,
		InstallID: authCode.InstallID,
	})
	if err != nil {
		tokenError(response, "server_error", http.StatusInternalServerError)
		return
	}
	refreshToken := newRefreshToken(authCode.UserID, authCode.ClientID, authCode.InstallID, authCode.Scopes)
	if err := handler.store.SaveRefreshToken(ctx, refreshToken); err != nil {
		slog.ErrorContext(ctx, "failed to save refresh token", "error", err)
		tokenError(response, "server_error", http.StatusInternalServerError)
		return
	}
	body := newTokenResponse(accessToken, refreshToken.ID, authCode.Scopes)
	if authCode.InstallID != "" {
		bundle, err := handler.store.GetInstallGrantBundle(ctx, authCode.InstallID)
		if err != nil {
			slog.ErrorContext(ctx, "install grants missing", "install_id", authCode.InstallID, "error", err)
			tokenError(response, "server_error", http.StatusInternalServerError)
			return
		}
		body.Grant = newNeoworksGrant(authCode.InstallID, bundle)
	}
	writeJSON(response, http.StatusOK, body)
}

func newRefreshToken(userID, clientID, installID string, tokenScopes []string) store.RefreshToken {
	now := time.Now()
	return store.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		ClientID:  clientID,
		InstallID: installID,
		Scopes:    tokenScopes,
		ExpiresAt: now.Add(tokens.RefreshTokenTTL),
		CreatedAt: now,
	}
}

// clientSecretFromRequest reads the client secret from the body or HTTP Basic.
func clientSecretFromRequest(request *http.Request) string {
	secret := request.FormValue("client_secret")
	if secret != "" {
		return secret
	}
	_, basicSecret, ok := request.BasicAuth()
	if !ok {
		return ""
	}
	return basicSecret
}

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/shared"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

type TokenHandler struct {
	codes   *cache.RedisStore
	tokens  *cache.RedisStore
	refresh *database.SurrealStore
	issuer  *oauth.TokenIssuer
}

func NewTokenHandler(
	codes *cache.RedisStore,
	tokens *cache.RedisStore,
	refresh *database.SurrealStore,
	issuer *oauth.TokenIssuer,
) *TokenHandler {
	return &TokenHandler{codes: codes, tokens: tokens, refresh: refresh, issuer: issuer}
}

func (h *TokenHandler) Register(r chi.Router) {
	r.Post("/oauth/token", h.handleToken)
}

func (h *TokenHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		h.handleAuthCode(w, r)
	case "refresh_token":
		h.handleRefresh(w, r)
	case "client_credentials":
		h.handleClientCredentials(w, r)
	default:
		tokenError(w, "unsupported_grant_type", http.StatusBadRequest)
	}
}

// handleClientCredentials issues a user-less access token for a confidential
// client authenticating with its secret — the client acting as its own
// organization. This is what authorizes org-scoped writes in the data plane.
// No refresh token is issued; the client re-requests when the token expires.
func (h *TokenHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := r.FormValue("client_id")
	if clientID == "" {
		if user, _, ok := r.BasicAuth(); ok {
			clientID = user
		}
	}
	if clientID == "" {
		tokenError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	client, err := h.refresh.GetClient(ctx, clientID)
	if err != nil {
		slog.WarnContext(ctx, "unknown client for client_credentials", "client_id", clientID, "error", err)
		tokenError(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	// Only clients that hold a secret may use this grant. A client can be public
	// (PKCE for user logins) and still carry a secret used solely for
	// client_credentials — the client acting as its own organization.
	if client.SecretHash == "" {
		slog.WarnContext(ctx, "client_credentials requires a client secret", "client_id", clientID)
		tokenError(w, "unauthorized_client", http.StatusBadRequest)
		return
	}
	secret := clientSecretFromRequest(r)
	if secret == "" || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) != nil {
		slog.WarnContext(ctx, "client secret verification failed", "client_id", clientID)
		tokenError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	// RFC 6749 §3.3: an omitted scope falls back to the client's registered
	// scopes; anything outside them is rejected rather than silently narrowed.
	scopes := strings.Fields(r.FormValue("scope"))
	if len(scopes) == 0 {
		scopes = client.Scopes
	}
	if !shared.ScopesAllowed(client.Scopes, scopes) {
		slog.WarnContext(ctx, "client_credentials requested scope outside client registration", "client_id", clientID, "scopes", scopes)
		tokenError(w, "invalid_scope", http.StatusBadRequest)
		return
	}
	clientRef := models.NewRecordID("client", clientID)
	accessToken, _, err := h.issuer.IssueAccessToken(nil, &clientRef, scopes)
	if err != nil {
		slog.ErrorContext(ctx, "failed to issue client_credentials token", "client_id", clientID, "error", err)
		tokenError(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeTokenResponse(w, accessToken, "", scopes)
}

func (h *TokenHandler) handleAuthCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" {
		slog.WarnContext(ctx, "missing authorization code")
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	if redirectURI == "" {
		slog.WarnContext(
			ctx, "missing redirect uri",
			"code_present", code != "",
		)
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Consume is atomic — GET + DEL in one pipeline
	authCode, err := h.codes.ConsumeAuthCode(ctx, code)
	if err != nil {
		slog.WarnContext(
			ctx, "failed to consume auth code",
			"error", err,
		)

		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	now := time.Now()
	if now.After(authCode.ExpiresAt) {
		slog.WarnContext(
			ctx, "auth code expired",
			"user_id", authCode.UserID,
			"client_id", authCode.ClientID,
			"expires_at", authCode.ExpiresAt.Format(time.RFC3339),
			"now", now.Format(time.RFC3339),
		)

		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	if authCode.RedirectURI != redirectURI {
		slog.WarnContext(
			ctx, "redirect uri mismatch",
			"user_id", authCode.UserID,
			"client_id", authCode.ClientID,
			"expected_redirect_uri", authCode.RedirectURI,
			"actual_redirect_uri", redirectURI,
		)

		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Authenticate the client. Confidential clients (those with a secret) prove
	// themselves with client_secret and skip PKCE; public clients use PKCE.
	clientKey, _ := authCode.ClientID.ID.(string)
	client, err := h.refresh.GetClient(ctx, clientKey)
	if err != nil {
		slog.WarnContext(ctx, "unknown client for auth code", "client_id", authCode.ClientID, "error", err)
		tokenError(w, "invalid_client", http.StatusBadRequest)
		return
	}

	if client.Public || client.SecretHash == "" {
		verifier := r.FormValue("code_verifier")
		if verifier == "" {
			slog.WarnContext(ctx, "missing code verifier", "client_id", authCode.ClientID)
			tokenError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		if err := oauth.VerifyPKCE(verifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			slog.WarnContext(
				ctx, "pkce verification failed",
				"user_id", authCode.UserID,
				"client_id", authCode.ClientID,
				"code_challenge_method", authCode.CodeChallengeMethod,
				"error", err,
			)

			tokenError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
	} else {
		secret := clientSecretFromRequest(r)
		if secret == "" || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret)) != nil {
			slog.WarnContext(ctx, "client secret verification failed", "client_id", authCode.ClientID)
			tokenError(w, "invalid_client", http.StatusUnauthorized)
			return
		}
	}

	// Issue tokens
	accessToken, _, err := h.issuer.IssueAccessToken(authCode.UserID, authCode.ClientID, authCode.Scopes)
	if err != nil {
		slog.ErrorContext(
			ctx, "failed to issue access token",
			"user_id", authCode.UserID,
			"client_id", authCode.ClientID,
			"scopes", authCode.Scopes,
			"error", err,
		)

		tokenError(w, "server_error", http.StatusInternalServerError)
		return
	}

	rt := h.issuer.IssueRefreshToken(authCode.UserID, authCode.ClientID, authCode.Scopes)

	if err := h.refresh.SaveRefreshToken(ctx, rt); err != nil {
		slog.ErrorContext(
			ctx, "failed to save refresh token",
			"refresh_token_id", rt.ID,
			"user_id", rt.User,
			"client_id", rt.Client,
			"error", err,
		)

		tokenError(w, "server_error", http.StatusInternalServerError)
		return
	}

	refreshTokenID, ok := rt.ID.ID.(string)
	if !ok {
		slog.ErrorContext(
			ctx, "invalid refresh token record id type",
			"refresh_token_id", rt.ID,
			"raw_id", rt.ID.ID,
			"raw_id_type", fmt.Sprintf("%T", rt.ID.ID),
		)

		tokenError(w, "server_error", http.StatusInternalServerError)
		return
	}

	writeTokenResponse(w, accessToken, refreshTokenID, authCode.Scopes)
}

// rotationGraceTTL must outlive the rotation lock (30s) so a request that loses
// the lock always finds the winner's cached result before the grace key expires.
const rotationGraceTTL = 60 * time.Second

func (h *TokenHandler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rawRefreshToken := r.FormValue("refresh_token")

	// Fetch from SurrealDB first — validate it exists and isn't revoked
	refreshToken, err := h.refresh.GetRefreshToken(ctx, rawRefreshToken)
	if err != nil {
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if refreshToken.Revoked {
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	jti := refreshToken.ID.ID.(string)

	// Already rotated within the grace window → hand back the same new tokens.
	// Covers concurrent requests, multi-tab refreshes and client retries.
	if cached, err := h.codes.GetRotationResult(ctx, jti); err == nil {
		writeCachedTokenResponse(w, cached)
		return
	}
	if refreshToken.Used {
		// Used and past the grace window — genuine replay of an old token.
		_ = h.refresh.RevokeGrant(ctx, refreshToken.User, refreshToken.Client)
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if time.Now().After(refreshToken.ExpiresAt) {
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Serialize rotation. Losing the lock means a concurrent request is rotating
	// this same token right now — wait for its result instead of revoking.
	if err := h.codes.AcquireRotationLock(ctx, jti); err != nil {
		if err == cache.ErrTokenReplayed {
			if cached := h.awaitRotationResult(ctx, jti); cached != nil {
				writeCachedTokenResponse(w, cached)
				return
			}
		}
		tokenError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// We hold the lock — perform the rotation.
	if err := h.refresh.MarkRefreshTokenUsed(ctx, jti); err != nil {
		tokenError(w, "server_error", http.StatusInternalServerError)
		return
	}

	accessToken, _, err := h.issuer.IssueAccessToken(refreshToken.User, refreshToken.Client, refreshToken.Scopes)
	if err != nil {
		tokenError(w, "server_error", http.StatusInternalServerError)
		return
	}

	newRT := h.issuer.IssueRefreshToken(refreshToken.User, refreshToken.Client, refreshToken.Scopes)
	if err := h.refresh.SaveRefreshToken(ctx, newRT); err != nil {
		tokenError(w, "server_error", http.StatusInternalServerError)
		return
	}

	resp := oauth.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(oauth.AccessTokenTTL.Seconds()),
		RefreshToken: newRT.ID.ID.(string),
		Scope:        strings.Join(refreshToken.Scopes, " "),
	}

	// Cache before responding so a concurrent loser can find it immediately.
	_ = h.codes.SaveRotationResult(ctx, jti, resp, rotationGraceTTL)

	writeCachedTokenResponse(w, &resp)
}

// awaitRotationResult polls for the result of a concurrent rotation that holds
// the lock, returning nil if none appears within the wait budget.
func (h *TokenHandler) awaitRotationResult(ctx context.Context, jti string) *oauth.TokenResponse {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cached, err := h.codes.GetRotationResult(ctx, jti); err == nil {
			return cached
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeTokenResponse(w http.ResponseWriter, accessToken, refreshToken string, scopes []string) {
	writeCachedTokenResponse(w, &oauth.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(oauth.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        strings.Join(scopes, " "),
	})
}

func writeCachedTokenResponse(w http.ResponseWriter, resp *oauth.TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// clientSecretFromRequest reads the client secret from the POST body or, failing
// that, HTTP Basic auth (RFC 6749 client authentication).
func clientSecretFromRequest(r *http.Request) string {
	if s := r.FormValue("client_secret"); s != "" {
		return s
	}
	if _, secret, ok := r.BasicAuth(); ok {
		return secret
	}
	return ""
}

func tokenError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

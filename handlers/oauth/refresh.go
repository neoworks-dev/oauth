package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/tokens"
)

// rotationGraceTTL must outlive the rotation lock so a request that loses the
// lock always finds the winner's result.
const rotationGraceTTL = 60 * time.Second

func (handler *TokenHandler) handleRefresh(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	refreshToken, err := handler.store.GetRefreshToken(ctx, request.FormValue("refresh_token"))
	if err != nil || refreshToken.Revoked {
		tokenError(response, "invalid_grant", http.StatusBadRequest)
		return
	}
	cached, err := handler.state.GetRotationResult(ctx, refreshToken.ID)
	if err == nil {
		writeRefreshResult(response, cached)
		return
	}
	if refreshToken.Used {
		handler.treatAsReplay(ctx, refreshToken)
		tokenError(response, "invalid_grant", http.StatusBadRequest)
		return
	}
	if time.Now().After(refreshToken.ExpiresAt) || !handler.installUsable(ctx, refreshToken) {
		tokenError(response, "invalid_grant", http.StatusBadRequest)
		return
	}
	handler.rotate(response, request, refreshToken)
}

// treatAsReplay revokes the grant when an already-rotated token comes back
// after the grace window.
func (handler *TokenHandler) treatAsReplay(ctx context.Context, refreshToken *store.RefreshToken) {
	_ = handler.store.RevokeRefreshTokensFor(ctx, refreshToken.UserID, refreshToken.ClientID)
}

func (handler *TokenHandler) installUsable(ctx context.Context, refreshToken *store.RefreshToken) bool {
	if refreshToken.InstallID == "" {
		return true
	}
	install, err := handler.store.GetInstall(ctx, refreshToken.InstallID)
	return err == nil && install.RevokedAt == nil
}

func (handler *TokenHandler) rotate(response http.ResponseWriter, request *http.Request, refreshToken *store.RefreshToken) {
	ctx := request.Context()
	err := handler.state.AcquireRotationLock(ctx, refreshToken.ID)
	if errors.Is(err, cache.ErrTokenReplayed) {
		handler.replayConcurrentRotation(response, request, refreshToken.ID)
		return
	}
	if err != nil {
		tokenError(response, "server_error", http.StatusInternalServerError)
		return
	}
	result, err := handler.performRotation(ctx, refreshToken)
	if err != nil {
		tokenError(response, "server_error", http.StatusInternalServerError)
		return
	}
	_ = handler.state.SaveRotationResult(ctx, refreshToken.ID, *result, rotationGraceTTL)
	writeRefreshResult(response, result)
}

func (handler *TokenHandler) performRotation(ctx context.Context, refreshToken *store.RefreshToken) (*cache.RefreshResult, error) {
	err := handler.store.MarkRefreshTokenUsed(ctx, refreshToken.ID)
	if err != nil {
		return nil, err
	}
	accessToken, _, err := handler.issuer.IssueAccessToken(tokens.AccessTokenParams{
		UserID:    refreshToken.UserID,
		ClientID:  refreshToken.ClientID,
		Scopes:    refreshToken.Scopes,
		InstallID: refreshToken.InstallID,
	})
	if err != nil {
		return nil, err
	}
	next := newRefreshToken(refreshToken.UserID, refreshToken.ClientID, refreshToken.InstallID, refreshToken.Scopes)
	err = handler.store.SaveRefreshToken(ctx, next)
	if err != nil {
		return nil, err
	}
	return &cache.RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: next.ID,
		ExpiresIn:    int(tokens.AccessTokenTTL.Seconds()),
		Scope:        strings.Join(refreshToken.Scopes, " "),
	}, nil
}

// replayConcurrentRotation waits for the in-flight rotation of the same token
// and answers with its result.
func (handler *TokenHandler) replayConcurrentRotation(response http.ResponseWriter, request *http.Request, tokenID string) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cached, err := handler.state.GetRotationResult(request.Context(), tokenID)
		if err == nil {
			writeRefreshResult(response, cached)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	tokenError(response, "invalid_grant", http.StatusBadRequest)
}

func writeRefreshResult(response http.ResponseWriter, result *cache.RefreshResult) {
	body := tokenResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
		Scope:        result.Scope,
	}
	writeJSON(response, http.StatusOK, body)
}

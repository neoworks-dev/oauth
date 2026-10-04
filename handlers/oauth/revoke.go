package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/internal/tokens"
)

// TokenRevoker marks access tokens revoked.
type TokenRevoker interface {
	RevokeAccessToken(ctx context.Context, tokenID string, expiresAt time.Time) error
}

type RevokeHandler struct {
	issuer  *tokens.Issuer
	revoker TokenRevoker
	store   Store
}

func NewRevokeHandler(issuer *tokens.Issuer, revoker TokenRevoker, revokeStore Store) *RevokeHandler {
	return &RevokeHandler{issuer: issuer, revoker: revoker, store: revokeStore}
}

func (handler *RevokeHandler) Register(router chi.Router) {
	router.Post("/oauth/revoke", handler.handleRevoke)
}

// handleRevoke always answers 200, as RFC 7009 requires.
func (handler *RevokeHandler) handleRevoke(response http.ResponseWriter, request *http.Request) {
	defer response.WriteHeader(http.StatusOK)
	if err := request.ParseForm(); err != nil {
		return
	}
	raw := request.FormValue("token")
	if raw == "" {
		return
	}
	if request.FormValue("token_type_hint") != "refresh_token" && handler.revokeAccessToken(request.Context(), raw) {
		return
	}
	handler.revokeRefreshToken(request.Context(), raw)
}

func (handler *RevokeHandler) revokeAccessToken(ctx context.Context, raw string) bool {
	claims, err := handler.issuer.VerifyAccessToken(raw)
	if err != nil {
		return false
	}
	_ = handler.revoker.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Time)
	return true
}

func (handler *RevokeHandler) revokeRefreshToken(ctx context.Context, raw string) {
	refreshToken, err := handler.store.GetRefreshToken(ctx, raw)
	if err != nil {
		return
	}
	_ = handler.store.RevokeRefreshToken(ctx, refreshToken.ID)
}

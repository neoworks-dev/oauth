package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
)

type RevokeHandler struct {
	issuer  *oauth.TokenIssuer
	tokens  *cache.RedisStore
	refresh *database.SurrealStore
}

func NewRevokeHandler(
	issuer *oauth.TokenIssuer,
	tokens *cache.RedisStore,
	refresh *database.SurrealStore,
) *RevokeHandler {
	return &RevokeHandler{issuer: issuer, tokens: tokens, refresh: refresh}
}

func (h *RevokeHandler) Register(r chi.Router) {
	r.Post("/oauth/revoke", h.handleRevoke)
}

func (h *RevokeHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusOK) // spec says always 200
		return
	}

	raw := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint") // "access_token" or "refresh_token"

	if raw == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Try access token first unless hint says otherwise
	if tokenTypeHint != "refresh_token" {
		if claims, err := h.issuer.VerifyAccessToken(raw); err == nil {
			remaining := time.Until(claims.ExpiresAt.Time)
			if remaining > 0 {
				_ = h.tokens.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Time)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Try refresh token — raw value is the jti
	if rt, err := h.refresh.GetRefreshToken(ctx, raw); err == nil {
		_ = h.refresh.RevokeRefreshToken(ctx, rt.ID.ID.(string))
		w.WriteHeader(http.StatusOK)
		return
	}

	// Spec says return 200 even if token wasn't found
	w.WriteHeader(http.StatusOK)
}


package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
)

type IntrospectHandler struct {
	issuer *oauth.TokenIssuer
	tokens *cache.RedisStore
}

func NewIntrospectHandler(issuer *oauth.TokenIssuer, tokens *cache.RedisStore) *IntrospectHandler {
	return &IntrospectHandler{issuer: issuer, tokens: tokens}
}

func (handler *IntrospectHandler) Register(router chi.Router) {
	router.Post("/oauth/introspect", handler.handleIntrospect)
}

func (handler *IntrospectHandler) handleIntrospect(response http.ResponseWriter, router *http.Request) {
	ctx := router.Context()

	if err := router.ParseForm(); err != nil {
		introspectInactive(response)
		return
	}

	raw := router.FormValue("token")
	if raw == "" {
		introspectInactive(response)
		return
	}

	// Step 1 — verify signature and expiry locally, no I/O
	claims, err := handler.issuer.VerifyAccessToken(raw)
	if err != nil {
		// Expired or invalid — no need to check Redis
		introspectInactive(response)
		return
	}

	// Step 2 — single Redis EXISTS to check revocation list
	revoked, err := handler.tokens.IsRevoked(ctx, claims.ID)
	if err != nil || revoked {
		introspectInactive(response)
		return
	}

	// Active — return claims
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(response).Encode(map[string]any{
		"active":     true,
		"sub":        claims.Subject,
		"client_id":  claims.ClientID,
		"scope":      strings.Join(claims.Scope, " "),
		"exp":        claims.ExpiresAt.Unix(),
		"iat":        claims.IssuedAt.Unix(),
		"iss":        claims.Issuer,
		"jti":        claims.ID,
		"token_type": "Bearer",
	})
}

func introspectInactive(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(response).Encode(map[string]any{"active": false})
}
package oauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/internal/tokens"
)

type IntrospectHandler struct {
	issuer      *tokens.Issuer
	revocations RevocationList
	store       Store
}

func NewIntrospectHandler(issuer *tokens.Issuer, revocations RevocationList, introspectStore Store) *IntrospectHandler {
	return &IntrospectHandler{issuer: issuer, revocations: revocations, store: introspectStore}
}

func (handler *IntrospectHandler) Register(router chi.Router) {
	router.Post("/oauth/introspect", handler.handleIntrospect)
}

func (handler *IntrospectHandler) handleIntrospect(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	if err := request.ParseForm(); err != nil {
		writeInactive(response)
		return
	}
	claims, err := handler.issuer.VerifyAccessToken(request.FormValue("token"))
	if err != nil {
		writeInactive(response)
		return
	}
	revoked, err := handler.revocations.IsRevoked(ctx, claims.ID)
	if err != nil || revoked || !handler.installActive(ctx, claims) {
		writeInactive(response)
		return
	}
	writeJSON(response, http.StatusOK, introspectionBody(claims))
}

// installActive treats a token bound to a revoked or unknown install as inactive.
func (handler *IntrospectHandler) installActive(ctx context.Context, claims *tokens.Claims) bool {
	if claims.InstallID == "" {
		return true
	}
	install, err := handler.store.GetInstall(ctx, claims.InstallID)
	return err == nil && install.RevokedAt == nil
}

func introspectionBody(claims *tokens.Claims) map[string]any {
	body := map[string]any{
		"active":     true,
		"sub":        claims.Subject,
		"client_id":  claims.ClientID,
		"scope":      strings.Join(claims.Scope, " "),
		"exp":        claims.ExpiresAt.Unix(),
		"iat":        claims.IssuedAt.Unix(),
		"iss":        claims.Issuer,
		"jti":        claims.ID,
		"token_type": "Bearer",
	}
	if claims.InstallID != "" {
		body["install_id"] = claims.InstallID
	}
	return body
}

func writeInactive(response http.ResponseWriter) {
	writeJSON(response, http.StatusOK, map[string]any{"active": false})
}

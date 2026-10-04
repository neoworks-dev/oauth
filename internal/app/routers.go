// Package app assembles the two HTTP routers of the service: the oauth origin
// for machine endpoints and the vault origin for the interactive account vault.
package app

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	googlehandler "github.com/neoworks/oauth/handlers/google"
	oauthhandlers "github.com/neoworks/oauth/handlers/oauth"
	staticassets "github.com/neoworks/oauth/handlers/static"
	vaulthandler "github.com/neoworks/oauth/handlers/vault"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/signing"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/tokens"
)

// OAuthDependencies are what the oauth origin needs.
type OAuthDependencies struct {
	Store        *store.Store
	State        *cache.Store
	Issuer       *tokens.Issuer
	Keys         *signing.KeyManager
	Vault        *vaulthandler.Server
	IssuerURL    string
	VaultURL     string
	GoogleConfig googlehandler.Config
	GoogleClient googlehandler.Doer
}

// NewOAuthRouter builds the router of the oauth origin.
func NewOAuthRouter(deps OAuthDependencies) http.Handler {
	router := chi.NewRouter()
	router.Use(machineCORS)

	oauthhandlers.NewAuthorizeHandler(deps.Store, deps.State, deps.VaultURL).Register(router)
	oauthhandlers.NewTokenHandler(deps.State, deps.Store, deps.Issuer).Register(router)
	oauthhandlers.NewErrorPageHandler().Register(router)
	oauthhandlers.NewJWKSHandler(deps.Keys).Register(router)
	oauthhandlers.NewDiscoveryHandler(deps.IssuerURL).Register(router)
	staticassets.NewHandler().Register(router)
	deps.Vault.AuthenticatorRouter(router)

	bearer := oauthhandlers.RequireBearer(deps.Issuer, deps.State)
	googlehandler.NewHandler(deps.GoogleConfig, deps.GoogleClient).Register(router, bearer)
	router.Group(func(protected chi.Router) {
		protected.Use(bearer)
		oauthhandlers.NewIntrospectHandler(deps.Issuer, deps.State, deps.Store).Register(protected)
		oauthhandlers.NewRevokeHandler(deps.Issuer, deps.State, deps.Store).Register(protected)
		oauthhandlers.NewUserInfoHandler(deps.Store).Register(protected)
	})
	return router
}

// machineCORS lets browser apps call the token endpoints. The interactive
// pages live on the vault origin, which sends no CORS headers.
func machineCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Access-Control-Allow-Origin", "*")
		response.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		response.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if request.Method == http.MethodOptions {
			response.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(response, request)
	})
}

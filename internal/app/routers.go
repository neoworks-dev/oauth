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
	"github.com/neoworks/oauth/internal/ratelimit"
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
	// Limiter limits the authorize and token endpoints; nil turns the limits off.
	Limiter *ratelimit.Limiter
}

// NewOAuthRouter builds the router of the oauth origin.
func NewOAuthRouter(deps OAuthDependencies) http.Handler {
	router := chi.NewRouter()
	router.Use(machineCORS)

	oauthhandlers.NewAuthorizeHandler(deps.Store, deps.State, deps.VaultURL).Register(limited(router, deps.Limiter, ratelimit.BucketAuthorize, ratelimit.QueryClientID))
	oauthhandlers.NewTokenHandler(deps.State, deps.Store, deps.Issuer).Register(limited(router, deps.Limiter, ratelimit.BucketToken, ratelimit.FormClientID))
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

// limited returns the router the endpoints of a bucket register on: with the
// limiter in front of them, or the router itself when there is none.
func limited(router chi.Router, limiter *ratelimit.Limiter, bucket ratelimit.Bucket, clientOf ratelimit.ClientIDFunc) chi.Router {
	if limiter == nil {
		return router
	}
	return router.With(limiter.Middleware(bucket, clientOf))
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

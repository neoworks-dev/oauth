package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	"github.com/neoworks/auth/config"
	"github.com/neoworks/auth/crypto"
	"github.com/neoworks/auth/email"
	keyshandlers "github.com/neoworks/auth/handlers/keys"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/oauth/handlers"
	"github.com/neoworks/oauth/handlers/account"
	"github.com/neoworks/oauth/handlers/auth"
	fedcmhandler "github.com/neoworks/oauth/handlers/fedcm"
	oauth_handlers "github.com/neoworks/oauth/handlers/oauth"
	sessionhandler "github.com/neoworks/oauth/handlers/session"
	staticassets "github.com/neoworks/oauth/handlers/static"
	vaulthandler "github.com/neoworks/oauth/handlers/vault"
	"github.com/neoworks/oauth/middleware/sso"
)

func main() {
	_ = godotenv.Load(".env")
	setupLogger()

	slog.Info("Starting oauth server")

	// ── Config ────────────────────────────────────────────────────────────────
	keyPath := env("KEY_PATH", "./keys/auth.pem")
	redisAddr := env("REDIS_URL", "127.0.0.1:6379")
	surrealURL := env("SURREAL_URL", "ws://127.0.0.1:8000")
	surrealUser := env("SURREAL_USER", "root")
	surrealPass := env("SURREAL_PASS", "root")
	surrealNS := env("SURREAL_NS", "neoworks")
	surrealDB := env("SURREAL_DB", "auth")
	issuerURL := env("ISSUER_URL", config.ServiceURL("oauth"))
	loginURL := env("LOGIN_URL", config.ServiceURL("")+"/auth/login")
	port := env("PORT", "8080")
	debug := os.Getenv("DEBUG") == "true"

	// ── Keys ──────────────────────────────────────────────────────────────────
	keys, err := crypto.NewKeyManager(keyPath)
	if err != nil {
		log.Fatalf("key manager: %v", err)
	}

	// ── Storage ───────────────────────────────────────────────────────────────
	redis := cache.NewRedisStore(cache.Config{
		Addr: redisAddr,
	})

	surreal, err := database.NewSurrealStore(
		surrealURL, surrealUser, surrealPass, surrealNS, surrealDB,
	)
	if err != nil {
		log.Fatalf("surrealdb: %v", err)
	}

	// ── Core ──────────────────────────────────────────────────────────────────
	issuer := oauth.NewTokenIssuer(keys.PrivateKey(), issuerURL)
	pushSender := push.NewSender(push.ConfigFromEnv())
	mailer := email.NewSender(email.ConfigFromEnv())

	// ── Middleware ────────────────────────────────────────────────────────────
	clientAuth := middleware.NewJWTMiddleware(issuer, redis)

	// ── Router ────────────────────────────────────────────────────────────────
	router := chi.NewRouter()
	router.Use(chimiddleware.Logger)
	router.Use(chimiddleware.Recoverer)
	router.Use(chimiddleware.RealIP)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Public endpoints — no client auth
	oauth_handlers.NewAuthorizeHandler(surreal, redis, loginURL).Register(router)
	oauth_handlers.NewTokenHandler(redis, redis, surreal, issuer).Register(router)
	oauth_handlers.NewErrorPageHandler().Register(router)
	staticassets.NewHandler().Register(router)
	sessionhandler.NewHandler(surreal, redis).Register(router)
	fedcmhandler.NewHandler(surreal, redis, issuer, issuerURL).Register(router)
	handlers.NewJWKSHandler(keys).Register(router)

	// OpenID discovery
	router.Get("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"issuer": "` + issuerURL + `",
			"authorization_endpoint": "` + issuerURL + `/oauth/authorize",
			"token_endpoint": "` + issuerURL + `/oauth/token",
			"introspection_endpoint": "` + issuerURL + `/oauth/introspect",
			"revocation_endpoint": "` + issuerURL + `/oauth/revoke",
			"jwks_uri": "` + issuerURL + `/.well-known/jwks.json",
			"response_types_supported": ["code"],
			"grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
			"code_challenge_methods_supported": ["S256"],
			"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"]
		}`))
	})

	// Protected endpoints — require client auth
	router.Group(func(r chi.Router) {
		r.Use(clientAuth.JWTMiddleware)
		handlers.NewIntrospectHandler(issuer, redis).Register(r)
		handlers.NewRevokeHandler(issuer, redis, surreal).Register(r)
		handlers.NewUserInfoHandler(surreal, issuer).Register(r)
	})

	// User-facing endpoints — no client auth middleware
	router.Group(func(r chi.Router) {
		auth.NewLoginHandler(redis, surreal, issuer, loginURL).Register(r)
		auth.NewSelectAccountHandler(redis, surreal, issuer, loginURL).Register(r)
		auth.NewSignupHandler(redis, surreal, issuer, mailer, debug, loginURL).Register(r)
		auth.NewRecoveryHandler(redis, surreal, mailer, debug).Register(r)
		auth.NewScopesHandler(redis, surreal, loginURL).Register(r)
		auth.NewApprovalLoginHandler(redis, surreal, issuer, pushSender).Register(r)
		handlers.NewConsentHandler(redis, surreal, issuer, loginURL).Register(r)
		account.NewSecurityHandler(surreal, redis).Register(r)
	})

	// End-to-end encryption key & device management, reused from apps/api.
	// Public endpoints (key challenge, device-invite create/poll) need no auth;
	// authenticated endpoints are bridged from the sso_session cookie set by
	// /auth/login and /auth/signup, since this is all same-origin.
	keysHandler := keyshandlers.NewHandler(surreal, redis)
	keysHandler.RegisterPublic(router)
	router.Group(func(r chi.Router) {
		r.Use(sso.RequireSession(redis))
		keysHandler.RegisterAuthenticated(r)
	})

	// ── Callback endpoints (called by SvelteKit after login/consent) ──────────
	oauth_handlers.NewCallbackHandler(redis, surreal, issuer).Register(router)

	// Cross-origin crypto sandbox (embedded by client apps like muse).
	vaulthandler.NewHandler(surreal).Register(router)

	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

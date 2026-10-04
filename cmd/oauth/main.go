package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	googlehandler "github.com/neoworks/oauth/handlers/google"
	vaulthandler "github.com/neoworks/oauth/handlers/vault"
	"github.com/neoworks/oauth/internal/app"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/config"
	"github.com/neoworks/oauth/internal/mail"
	"github.com/neoworks/oauth/internal/signing"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/tokens"
)

func main() {
	_ = godotenv.Load(".env")
	setupLogger()
	slog.Info("Starting oauth server")

	ctx := context.Background()
	keys, err := signing.NewKeyManager(config.Env("KEY_PATH", "./keys/auth.pem"))
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	redis := cache.New(cache.ConfigFromEnv())
	database, err := store.Open(ctx,
		config.Env("SURREAL_URL", "ws://127.0.0.1:8000"),
		config.Env("SURREAL_USER", "root"),
		config.Env("SURREAL_PASS", "root"),
		config.Env("SURREAL_NS", "neoworks"),
		config.Env("SURREAL_DB", "auth"),
	)
	if err != nil {
		log.Fatalf("surrealdb: %v", err)
	}

	issuerURL := config.Env("ISSUER_URL", config.ServiceURL("oauth"))
	vaultURL := config.Env("VAULT_URL", config.ServiceURL("vault"))
	issuer := tokens.NewIssuer(keys.PrivateKey(), issuerURL)
	debug := os.Getenv("DEBUG") == "true"

	vault := vaulthandler.NewServer(vaulthandler.Config{
		VaultURL:       vaultURL,
		APIURL:         config.Env("API_URL", config.ServiceURL("api")),
		OAuthURL:       issuerURL,
		Debug:          debug,
		SecureCookies:  config.SecureCookies(),
		PreloginSecret: preloginSecret(keys),
	}, database, redis, issuer, mail.NewSender(mail.ConfigFromEnv()), escrowFromEnv())

	oauthRouter := chi.NewRouter()
	oauthRouter.Use(chimiddleware.Logger, chimiddleware.Recoverer, chimiddleware.RealIP)
	oauthRouter.Mount("/", app.NewOAuthRouter(app.OAuthDependencies{
		Store: database, State: redis, Issuer: issuer, Keys: keys, Vault: vault,
		IssuerURL: issuerURL, VaultURL: vaultURL,
		GoogleConfig: googlehandler.ConfigFromEnv(), GoogleClient: http.DefaultClient,
	}))
	vaultRouter := chi.NewRouter()
	vaultRouter.Use(chimiddleware.Logger, chimiddleware.Recoverer, chimiddleware.RealIP)
	vaultRouter.Mount("/", vault.Router())

	go serve("vault", ":"+config.Env("VAULT_PORT", "8087"), vaultRouter)
	serve("oauth", ":"+config.Env("PORT", "8080"), oauthRouter)
}

// preloginSecret is the key behind the fake parameters shown for unknown
// emails. PRELOGIN_SECRET overrides the secret derived from the signing key.
func preloginSecret(keys *signing.KeyManager) []byte {
	configured := os.Getenv("PRELOGIN_SECRET")
	if configured != "" {
		return []byte(configured)
	}
	return keys.DerivedSecret("prelogin")
}

func serve(name, address string, handler http.Handler) {
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	slog.Info("listening", "server", name, "address", address)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("%s server: %v", name, err)
	}
}

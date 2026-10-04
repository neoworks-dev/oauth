// Command devstack runs the oauth service on throwaway infrastructure: an
// in-memory SurrealDB and an in-process Redis. It exists for browser tests and
// local experiments and prints one READY line when both origins are up.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	googlehandler "github.com/neoworks/oauth/handlers/google"
	vaulthandler "github.com/neoworks/oauth/handlers/vault"
	"github.com/neoworks/oauth/internal/app"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/escrow"
	"github.com/neoworks/oauth/internal/signing"
	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/tokens"
)

func main() {
	oauthPort := flag.Int("oauth-port", 18080, "port of the oauth origin")
	vaultPort := flag.Int("vault-port", 18087, "port of the vault origin")
	escrowPort := flag.Int("escrow-port", 18090, "port of the escrow service")
	escrowWait := flag.Duration("escrow-wait", 3*time.Second, "escrow recovery waiting period")
	flag.Parse()

	surreal, err := testsupport.StartSurreal()
	if err != nil || surreal == nil {
		log.Fatalf("devstack needs the surreal binary: %v", err)
	}
	defer surreal.Stop()
	redisServer, err := miniredis.Run()
	if err != nil {
		log.Fatal(err)
	}
	defer redisServer.Close()

	oauthURL := fmt.Sprintf("http://localhost:%d", *oauthPort)
	vaultURL := fmt.Sprintf("http://localhost:%d", *vaultPort)
	seedClients(surreal, oauthURL)

	state := cache.New(cache.Config{Addr: redisServer.Addr()})
	keys, err := signing.NewKeyManager(os.TempDir() + "/devstack-signing.pem")
	if err != nil {
		log.Fatal(err)
	}
	issuer := tokens.NewIssuer(keys.PrivateKey(), oauthURL)
	inbox := &mailbox{}
	escrowURL, escrowHandler := startEscrow(inbox, vaultURL, *escrowPort, *escrowWait)
	vault := vaulthandler.NewServer(vaulthandler.Config{
		VaultURL: vaultURL, APIURL: oauthURL, OAuthURL: oauthURL, Debug: true,
		PreloginSecret: keys.DerivedSecret("prelogin"), AuthenticatorClientID: "neoworks-authenticator",
		CodeSendMaxPerIP: 10000,
	}, surreal.Store, state, issuer, inbox, vaulthandler.NewHTTPEscrow(escrowURL, devEscrowToken))
	oauthRouter := app.NewOAuthRouter(app.OAuthDependencies{
		Store: surreal.Store, State: state, Issuer: issuer, Keys: keys, Vault: vault,
		IssuerURL: oauthURL, VaultURL: vaultURL,
		GoogleConfig: googlehandler.Config{}, GoogleClient: http.DefaultClient,
	})
	vaultRouter := chi.NewRouter()
	vaultRouter.Mount("/", vault.Router())

	go listen(*escrowPort, escrowHandler)
	go listen(*oauthPort, inbox.handler(oauthRouter))
	go listen(*vaultPort, vaultRouter)
	fmt.Printf("READY oauth=%s vault=%s\n", oauthURL, vaultURL)
	waitForInterrupt()
}

const devEscrowToken = "devstack-escrow-token"

// startEscrow builds the escrow service on in-memory storage with the
// development keys and returns its URL and handler.
func startEscrow(inbox *mailbox, vaultURL string, port int, waiting time.Duration) (string, http.Handler) {
	service := escrow.NewService(escrow.NewMemoryRepository(), escrow.NewMemoryKMS(), inbox, escrow.DevServiceKey(),
		escrow.Config{WaitingPeriod: waiting, CancelBaseURL: vaultURL + "/recover/cancel"}, time.Now)
	return fmt.Sprintf("http://localhost:%d", port), escrow.NewHandler(service, devEscrowToken)
}

func seedClients(surreal *testsupport.Surreal, oauthURL string) {
	redirects := []string{"http://localhost:19000/callback"}
	scopes := []string{
		"openid", "profile", "email", "calendar:read", "calendar:write", "contacts:read", "contacts:write",
		"photos:read", "photos:write", "files:read", "files:write",
	}
	if err := surreal.CreateClient("e2e-app", redirects, scopes, false); err != nil {
		log.Fatal(err)
	}
	if err := surreal.CreateClient("e2e-first-party", redirects, scopes, true); err != nil {
		log.Fatal(err)
	}
	identityScopes := []string{"openid", "profile", "email"}
	if err := surreal.CreateClient("neoworks-authenticator", redirects, identityScopes, true); err != nil {
		log.Fatal(err)
	}
}

func listen(port int, handler http.Handler) {
	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func waitForInterrupt() {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	<-interrupts
}

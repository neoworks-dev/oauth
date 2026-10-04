// Command escrow runs the opt-in key escrow service: a separate process with its
// own SurrealDB namespace and its own KMS key. The main API never sees its data.
//
//	escrow          serve the API
//	escrow pubkey   print the service's public key for pinning in the vault build
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/neoworks/oauth/internal/config"
	"github.com/neoworks/oauth/internal/escrow"
	"github.com/neoworks/oauth/internal/mail"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx := context.Background()
	development := os.Getenv("ESCROW_DEV") == "true"
	kms, err := escrow.LoadFileKMS(config.Env("ESCROW_KMS_KEY_FILE", "./keys/escrow-kms.key"), development)
	if err != nil {
		log.Fatalf("kms: %v", err)
	}
	repository, err := escrow.OpenSurreal(ctx,
		config.Env("ESCROW_SURREAL_URL", "ws://127.0.0.1:8000"),
		config.Env("ESCROW_SURREAL_USER", "root"),
		config.Env("ESCROW_SURREAL_PASS", "root"),
		config.Env("ESCROW_SURREAL_NS", "escrow"),
		config.Env("ESCROW_SURREAL_DB", "escrow"))
	if err != nil {
		log.Fatalf("surrealdb: %v", err)
	}
	if err := repository.DefineSchema(ctx); err != nil {
		log.Fatalf("schema: %v", err)
	}
	key, err := escrow.LoadOrCreateServiceKey(ctx, repository, kms, development)
	if err != nil {
		log.Fatalf("service key: %v", err)
	}
	if len(os.Args) > 1 && os.Args[1] == "pubkey" {
		fmt.Println(base64.RawURLEncoding.EncodeToString(key.Public[:]))
		return
	}
	serve(repository, kms, key)
}

func serve(repository escrow.Repository, kms escrow.KMS, key escrow.ServiceKey) {
	serviceToken := os.Getenv("ESCROW_SERVICE_TOKEN")
	if serviceToken == "" {
		log.Fatal("ESCROW_SERVICE_TOKEN is required")
	}
	waiting, err := time.ParseDuration(config.Env("ESCROW_WAIT", "168h"))
	if err != nil {
		log.Fatalf("ESCROW_WAIT: %v", err)
	}
	service := escrow.NewService(repository, kms, mail.NewSender(mail.ConfigFromEnv()), key, escrow.Config{
		WaitingPeriod: waiting,
		CancelBaseURL: config.Env("VAULT_URL", config.ServiceURL("vault")) + "/recover/cancel",
	}, time.Now)
	address := ":" + config.Env("ESCROW_PORT", "8090")
	server := &http.Server{Addr: address, Handler: escrow.NewHandler(service, serviceToken), ReadHeaderTimeout: 10 * time.Second}
	slog.Info("escrow listening", "address", address, "waiting", waiting.String())
	log.Fatal(server.ListenAndServe())
}

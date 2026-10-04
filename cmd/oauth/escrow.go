package main

import (
	"os"

	vaulthandler "github.com/neoworks/oauth/handlers/vault"
)

// escrowFromEnv returns the escrow client when ESCROW_URL is configured.
func escrowFromEnv() vaulthandler.Escrow {
	baseURL := os.Getenv("ESCROW_URL")
	token := os.Getenv("ESCROW_SERVICE_TOKEN")
	if baseURL == "" || token == "" {
		return vaulthandler.NoEscrow{}
	}
	return vaulthandler.NewHTTPEscrow(baseURL, token)
}

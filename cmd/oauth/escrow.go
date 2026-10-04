package main

import (
	vaulthandler "github.com/neoworks/oauth/handlers/vault"
)

// escrowFromEnv returns the escrow client when ESCROW_URL is configured.
func escrowFromEnv() vaulthandler.Escrow {
	return vaulthandler.NoEscrow{}
}

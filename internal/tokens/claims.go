// Package tokens issues and verifies Neoworks access tokens.
package tokens

import (
	"errors"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 30 * 24 * time.Hour

	// VaultClientID identifies tokens minted for the account vault itself. They
	// carry no install and act as the user principal.
	VaultClientID = "neoworks.vault"
)

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
)

// Claims is the access token payload. InstallID is empty for the account vault.
type Claims struct {
	jwt.RegisteredClaims
	ClientID  string   `json:"client_id"`
	Scope     []string `json:"scope"`
	InstallID string   `json:"install_id,omitempty"`
}

func (claims *Claims) HasScope(scope string) bool {
	return slices.Contains(claims.Scope, scope)
}

// Package oauth serves the machine-facing OAuth 2.0 endpoints: authorize
// (which hands the browser to the account vault), token, introspection,
// revocation, userinfo, JWKS and discovery.
package oauth

import (
	"context"

	"github.com/neoworks/oauth/internal/store"
)

// Store is the database slice the OAuth endpoints need.
type Store interface {
	GetClient(ctx context.Context, clientID string) (*store.Client, error)
	GetUserByID(ctx context.Context, userID string) (*store.User, error)
	GetRefreshToken(ctx context.Context, tokenID string) (*store.RefreshToken, error)
	SaveRefreshToken(ctx context.Context, token store.RefreshToken) error
	MarkRefreshTokenUsed(ctx context.Context, tokenID string) error
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeRefreshTokensFor(ctx context.Context, userID, clientID string) error
	GetInstall(ctx context.Context, installID string) (*store.Install, error)
	GetInstallGrantBundle(ctx context.Context, installID string) (*store.InstallGrantBundle, error)
}

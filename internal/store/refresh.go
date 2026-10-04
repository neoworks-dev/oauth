package store

import (
	"context"
	"time"
)

type RefreshToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user"`
	ClientID  string    `json:"client"`
	InstallID string    `json:"install"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
	Used      bool      `json:"used"`
}

const refreshColumns = `record::id(id) AS id, record::id(user) AS user, record::id(client) AS client,
	IF install != NONE THEN record::id(install) END AS install, scopes, expires_at, created_at, revoked, used`

func (store *Store) SaveRefreshToken(ctx context.Context, token RefreshToken) error {
	fields := map[string]any{
		"user":       recordID("user", token.UserID),
		"client":     recordID("client", token.ClientID),
		"scopes":     token.Scopes,
		"expires_at": token.ExpiresAt,
		"created_at": token.CreatedAt,
		"used":       false,
		"revoked":    false,
	}
	if token.InstallID != "" {
		fields["install"] = recordID("install", token.InstallID)
	}
	return execute(ctx, store, "CREATE $id CONTENT $fields", map[string]any{
		"id":     recordID("refresh_token", token.ID),
		"fields": fields,
	})
}

func (store *Store) GetRefreshToken(ctx context.Context, tokenID string) (*RefreshToken, error) {
	return firstRow[RefreshToken](ctx, store,
		"SELECT "+refreshColumns+" FROM refresh_token WHERE id = $id LIMIT 1",
		map[string]any{"id": recordID("refresh_token", tokenID)})
}

func (store *Store) MarkRefreshTokenUsed(ctx context.Context, tokenID string) error {
	return execute(ctx, store, "UPDATE $id SET used = true",
		map[string]any{"id": recordID("refresh_token", tokenID)})
}

func (store *Store) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	return execute(ctx, store, "UPDATE $id SET revoked = true",
		map[string]any{"id": recordID("refresh_token", tokenID)})
}

// RevokeRefreshTokensFor revokes every refresh token of a user for one client.
func (store *Store) RevokeRefreshTokensFor(ctx context.Context, userID, clientID string) error {
	return execute(ctx, store,
		"UPDATE refresh_token SET revoked = true WHERE user = $user AND client = $client",
		map[string]any{"user": recordID("user", userID), "client": recordID("client", clientID)})
}

package cache

import (
	"context"
	"time"
)

const VaultSessionTTL = 30 * 24 * time.Hour

// VaultSession is a browser's login to the account vault.
type VaultSession struct {
	UserID    string    `json:"user_id"`
	DeviceID  string    `json:"device_id"`
	CreatedAt time.Time `json:"created_at"`
}

func (store *Store) SaveVaultSession(ctx context.Context, token string, session VaultSession) error {
	return store.saveJSON(ctx, "vault_session:"+token, session, VaultSessionTTL)
}

func (store *Store) GetVaultSession(ctx context.Context, token string) (*VaultSession, error) {
	var session VaultSession
	err := store.getJSON(ctx, "vault_session:"+token, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (store *Store) DeleteVaultSession(ctx context.Context, token string) error {
	return store.client.Del(ctx, "vault_session:"+token).Err()
}

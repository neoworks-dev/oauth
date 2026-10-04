package store

import (
	"context"
	"strings"
	"time"
)

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	FirstName     string    `json:"first_name"`
	LastName      string    `json:"last_name"`
	AuthHash      string    `json:"auth_hash"`
	EscrowEnabled bool      `json:"escrow_enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

const userColumns = `record::id(id) AS id, email, first_name, last_name, auth_hash,
	escrow_enabled, created_at`

func (store *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return firstRow[User](ctx, store,
		"SELECT "+userColumns+" FROM user WHERE email = $email LIMIT 1",
		map[string]any{"email": email})
}

func (store *Store) GetUserByID(ctx context.Context, userID string) (*User, error) {
	return firstRow[User](ctx, store,
		"SELECT "+userColumns+" FROM user WHERE id = $id LIMIT 1",
		map[string]any{"id": recordID("user", userID)})
}

func (store *Store) SetEscrowEnabled(ctx context.Context, userID string, enabled bool) error {
	return execute(ctx, store,
		"UPDATE $id SET escrow_enabled = $enabled",
		map[string]any{"id": recordID("user", userID), "enabled": enabled})
}

func isEmailTaken(err error) bool {
	return err != nil && strings.Contains(err.Error(), "email_taken")
}

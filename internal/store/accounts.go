package store

import (
	"context"
	"time"
)

// NewAccount is everything signup writes: the user, key bundle and first
// device. Collection roots come with the first consent that asks for them.
type NewAccount struct {
	UserID        string
	Email         string
	FirstName     string
	LastName      string
	AuthHash      string
	EscrowEnabled bool
	Bundle        KeyBundle
	Device        Device
}

// CreateAccount writes the whole account in one transaction. A registered email
// fails with ErrEmailTaken.
func (store *Store) CreateAccount(ctx context.Context, account NewAccount) error {
	now := time.Now().UTC()
	bundle := bundleFields(account.Bundle)
	bundle["user"] = recordID("user", account.UserID)
	err := execute(ctx, store, `
		BEGIN TRANSACTION;
		IF array::len((SELECT id FROM user WHERE email = $email)) > 0 {
			THROW "email_taken";
		};
		CREATE $user_id CONTENT {
			email: $email, first_name: $first_name, last_name: $last_name,
			auth_hash: $auth_hash, escrow_enabled: $escrow_enabled, created_at: $now
		};
		CREATE key_bundle CONTENT $bundle;
		CREATE identity_key SET user = $user_id, version = 1, sign_pub = $sign_pub, enc_pub = $enc_pub;
		CREATE $device_id CONTENT {
			user: $user_id, name: $device_name, kind: $device_kind,
			created_at: $now, last_seen_at: $now
		};
		COMMIT TRANSACTION;`,
		map[string]any{
			"user_id":        recordID("user", account.UserID),
			"email":          account.Email,
			"first_name":     account.FirstName,
			"last_name":      account.LastName,
			"auth_hash":      account.AuthHash,
			"escrow_enabled": account.EscrowEnabled,
			"now":            now,
			"bundle":         bundle,
			"sign_pub":       account.Bundle.SignPub,
			"enc_pub":        account.Bundle.EncPub,
			"device_id":      recordID("device", account.Device.ID),
			"device_name":    account.Device.Name,
			"device_kind":    account.Device.Kind,
		})
	if isEmailTaken(err) {
		return ErrEmailTaken
	}
	return err
}

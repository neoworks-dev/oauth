package store

import (
	"context"
	"time"
)

// NewAccount is everything signup writes: the user, key bundle, first device,
// root nodes and the owner's grants on them.
type NewAccount struct {
	UserID        string
	Email         string
	FirstName     string
	LastName      string
	AuthHash      string
	EscrowEnabled bool
	Bundle        KeyBundle
	Device        Device
	Nodes         []Node
	Grants        []AccessGrant
}

// CreateAccount writes the whole account in one transaction. A registered email
// fails with ErrEmailTaken.
func (store *Store) CreateAccount(ctx context.Context, account NewAccount) error {
	now := time.Now().UTC()
	nodeRows := make([]map[string]any, 0, len(account.Nodes))
	for _, node := range account.Nodes {
		nodeRows = append(nodeRows, nodeFields(node))
	}
	grantRows := make([]map[string]any, 0, len(account.Grants))
	logRows := make([]map[string]any, 0, len(account.Grants))
	for _, grant := range account.Grants {
		grantRows = append(grantRows, accessGrantFields(grant))
		logRows = append(logRows, accessLogFields(grant))
	}
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
		CREATE $device_id CONTENT {
			user: $user_id, name: $device_name, kind: $device_kind,
			created_at: $now, last_seen_at: $now
		};
		INSERT INTO node $node_rows;
		INSERT INTO access_grant $grant_rows;
		INSERT INTO access_log $log_rows;
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
			"device_id":      recordID("device", account.Device.ID),
			"device_name":    account.Device.Name,
			"device_kind":    account.Device.Kind,
			"node_rows":      nodeRows,
			"grant_rows":     grantRows,
			"log_rows":       logRows,
		})
	if isEmailTaken(err) {
		return ErrEmailTaken
	}
	return err
}

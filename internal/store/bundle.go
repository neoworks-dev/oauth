package store

import (
	"context"
	"time"
)

// KeyBundle is the server-held, opaque key material of an account. Binary
// values are base64url strings.
type KeyBundle struct {
	UserID          string `json:"userId"`
	Version         uint32 `json:"version"`
	PwhashSalt      string `json:"pwhashSalt"`
	PwhashOps       uint32 `json:"pwhashOps"`
	PwhashMem       uint64 `json:"pwhashMem"`
	AmkPassword     string `json:"amkPassword"`
	AmkRecovery     string `json:"amkRecovery"`
	IdentityPrivate string `json:"identityPrivate"`
	EncPub          string `json:"encPub"`
	SignPub         string `json:"signPub"`
	SelfSig         string `json:"selfSig"`
}

type keyBundleRow struct {
	UserID          string `json:"user"`
	Version         uint32 `json:"version"`
	PwhashSalt      string `json:"pwhash_salt"`
	PwhashOps       uint32 `json:"pwhash_ops"`
	PwhashMem       uint64 `json:"pwhash_mem"`
	AmkPassword     string `json:"amk_password"`
	AmkRecovery     string `json:"amk_recovery"`
	IdentityPrivate string `json:"identity_private"`
	EncPub          string `json:"enc_pub"`
	SignPub         string `json:"sign_pub"`
	SelfSig         string `json:"self_sig"`
}

const keyBundleColumns = `record::id(user) AS user, version, pwhash_salt, pwhash_ops,
	pwhash_mem, amk_password, amk_recovery, identity_private, enc_pub, sign_pub, self_sig`

func (row keyBundleRow) toBundle() *KeyBundle {
	bundle := KeyBundle(row)
	return &bundle
}

func (store *Store) GetKeyBundle(ctx context.Context, userID string) (*KeyBundle, error) {
	row, err := firstRow[keyBundleRow](ctx, store,
		"SELECT "+keyBundleColumns+" FROM key_bundle WHERE user = $user LIMIT 1",
		map[string]any{"user": recordID("user", userID)})
	if err != nil {
		return nil, err
	}
	return row.toBundle(), nil
}

func bundleFields(bundle KeyBundle) map[string]any {
	return map[string]any{
		"version":          bundle.Version,
		"pwhash_salt":      bundle.PwhashSalt,
		"pwhash_ops":       bundle.PwhashOps,
		"pwhash_mem":       bundle.PwhashMem,
		"amk_password":     bundle.AmkPassword,
		"amk_recovery":     bundle.AmkRecovery,
		"identity_private": bundle.IdentityPrivate,
		"enc_pub":          bundle.EncPub,
		"sign_pub":         bundle.SignPub,
		"self_sig":         bundle.SelfSig,
		"updated_at":       time.Now().UTC(),
	}
}

// PasswordChange replaces the password-derived material of an account while
// keeping the AMK, identity and bundle version.
type PasswordChange struct {
	UserID          string
	ExpectedVersion uint32
	AuthHash        string
	PwhashSalt      string
	PwhashOps       uint32
	PwhashMem       uint64
	AmkPassword     string
}

// ChangePassword swaps the password material atomically. It fails with
// ErrConflict if the bundle version moved since the caller read it.
func (store *Store) ChangePassword(ctx context.Context, change PasswordChange) error {
	updated, err := transactionRows[keyBundleRow](ctx, store, `
		BEGIN TRANSACTION;
		UPDATE user SET auth_hash = $auth_hash WHERE id = $user_record
			AND array::len((SELECT id FROM key_bundle WHERE user = $user_record AND version = $version)) = 1;
		UPDATE key_bundle SET
			pwhash_salt = $pwhash_salt, pwhash_ops = $pwhash_ops, pwhash_mem = $pwhash_mem,
			amk_password = $amk_password, updated_at = time::now()
			WHERE user = $user_record AND version = $version
			RETURN `+keyBundleColumns+`;
		COMMIT TRANSACTION;`,
		map[string]any{
			"user_record":  recordID("user", change.UserID),
			"version":      change.ExpectedVersion,
			"auth_hash":    change.AuthHash,
			"pwhash_salt":  change.PwhashSalt,
			"pwhash_ops":   change.PwhashOps,
			"pwhash_mem":   change.PwhashMem,
			"amk_password": change.AmkPassword,
		})
	if err != nil {
		return wrapQueryError("change password", err)
	}
	if len(updated) == 0 {
		return ErrConflict
	}
	return nil
}

// Rotation replaces the whole bundle with the next version.
type Rotation struct {
	UserID          string
	ExpectedVersion uint32
	AuthHash        string
	Bundle          KeyBundle
}

// RotateBundle installs a new bundle version atomically. Older or concurrent
// versions fail with ErrConflict.
func (store *Store) RotateBundle(ctx context.Context, rotation Rotation) error {
	fields := bundleFields(rotation.Bundle)
	fields["user_record"] = recordID("user", rotation.UserID)
	fields["expected_version"] = rotation.ExpectedVersion
	fields["auth_hash"] = rotation.AuthHash
	updated, err := transactionRows[keyBundleRow](ctx, store, `
		BEGIN TRANSACTION;
		UPDATE user SET auth_hash = $auth_hash WHERE id = $user_record
			AND array::len((SELECT id FROM key_bundle WHERE user = $user_record AND version = $expected_version)) = 1;
		UPDATE key_bundle SET
			version = $version, pwhash_salt = $pwhash_salt, pwhash_ops = $pwhash_ops,
			pwhash_mem = $pwhash_mem, amk_password = $amk_password, amk_recovery = $amk_recovery,
			identity_private = $identity_private, enc_pub = $enc_pub, sign_pub = $sign_pub,
			self_sig = $self_sig, updated_at = $updated_at
			WHERE user = $user_record AND version = $expected_version
			RETURN `+keyBundleColumns+`;
		COMMIT TRANSACTION;`, fields)
	if err != nil {
		return wrapQueryError("rotate bundle", err)
	}
	if len(updated) == 0 {
		return ErrConflict
	}
	return nil
}

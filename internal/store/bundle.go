package store

import (
	"context"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
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
	// Previous is the identity before an unfinished full rotation, wrapped under
	// the current AMK. It stays until every key is rewrapped to the new identity.
	Previous *PreviousIdentity `json:"previous"`
	// IdentityVersion is the history version of the bundle's identity: the
	// newest one recorded, or the next one while a full rotation is unfinished.
	IdentityVersion uint32 `json:"identityVersion"`
}

// PreviousIdentity is the identity a full rotation replaced.
type PreviousIdentity struct {
	IdentityPrivate string `json:"identityPrivate"`
	EncPub          string `json:"encPub"`
	SignPub         string `json:"signPub"`
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

	PreviousIdentityPrivate *string `json:"previous_identity_private"`
	PreviousEncPub          *string `json:"previous_enc_pub"`
	PreviousSignPub         *string `json:"previous_sign_pub"`
}

const keyBundleColumns = `record::id(user) AS user, version, pwhash_salt, pwhash_ops,
	pwhash_mem, amk_password, amk_recovery, identity_private, enc_pub, sign_pub, self_sig,
	previous_identity_private, previous_enc_pub, previous_sign_pub`

func (row keyBundleRow) toBundle() *KeyBundle {
	bundle := KeyBundle{
		UserID: row.UserID, Version: row.Version, PwhashSalt: row.PwhashSalt, PwhashOps: row.PwhashOps,
		PwhashMem: row.PwhashMem, AmkPassword: row.AmkPassword, AmkRecovery: row.AmkRecovery,
		IdentityPrivate: row.IdentityPrivate, EncPub: row.EncPub, SignPub: row.SignPub, SelfSig: row.SelfSig,
	}
	if row.PreviousIdentityPrivate != nil && row.PreviousEncPub != nil && row.PreviousSignPub != nil {
		bundle.Previous = &PreviousIdentity{
			IdentityPrivate: *row.PreviousIdentityPrivate, EncPub: *row.PreviousEncPub, SignPub: *row.PreviousSignPub,
		}
	}
	return &bundle
}

func (store *Store) GetKeyBundle(ctx context.Context, userID string) (*KeyBundle, error) {
	row, err := firstRow[keyBundleRow](ctx, store,
		"SELECT "+keyBundleColumns+" FROM key_bundle WHERE user = $user LIMIT 1",
		map[string]any{"user": recordID("user", userID)})
	if err != nil {
		return nil, err
	}
	bundle := row.toBundle()
	latest, err := store.LatestIdentityKey(ctx, userID)
	if err != nil {
		return nil, err
	}
	bundle.IdentityVersion = latest.Version
	if bundle.Previous != nil {
		bundle.IdentityVersion = latest.Version + 1
	}
	return bundle, nil
}

func bundleFields(bundle KeyBundle) map[string]any {
	fields := map[string]any{
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
	addPreviousFields(fields, bundle.Previous)
	return fields
}

func addPreviousFields(fields map[string]any, previous *PreviousIdentity) {
	if previous == nil {
		fields["previous_identity_private"] = models.None
		fields["previous_enc_pub"] = models.None
		fields["previous_sign_pub"] = models.None
		return
	}
	fields["previous_identity_private"] = previous.IdentityPrivate
	fields["previous_enc_pub"] = previous.EncPub
	fields["previous_sign_pub"] = previous.SignPub
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
			self_sig = $self_sig, updated_at = $updated_at,
			previous_identity_private = $previous_identity_private, previous_enc_pub = $previous_enc_pub,
			previous_sign_pub = $previous_sign_pub
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

// IdentityLink is the next identity version of a user, with the previous
// version's signature over its public keys.
type IdentityLink struct {
	Version     uint32
	SignPub     string
	EncPub      string
	RotationSig string
}

// CompleteRotation drops the previous identity once the client rewrapped every
// key to the new one, and appends the new identity to the user's key history
// while retiring the old one. It fails with ErrConflict when the bundle moved
// on or has no unfinished rotation.
func (store *Store) CompleteRotation(ctx context.Context, userID string, bundleVersion uint32, link IdentityLink) error {
	updated, err := transactionRows[keyBundleRow](ctx, store, `
		BEGIN TRANSACTION;
		LET $completed = IF array::len((SELECT id FROM key_bundle
				WHERE user = $user_record AND version = $bundle_version AND previous_sign_pub != NONE)) = 1 {
			UPDATE identity_key SET retired_at = time::now()
				WHERE user = $user_record AND version = $identity_version - 1;
			CREATE identity_key SET user = $user_record, version = $identity_version,
				sign_pub = $sign_pub, enc_pub = $enc_pub, rotation_sig = $rotation_sig;
			UPDATE key_bundle SET previous_identity_private = NONE, previous_enc_pub = NONE,
				previous_sign_pub = NONE, updated_at = time::now()
				WHERE user = $user_record AND version = $bundle_version
				RETURN `+keyBundleColumns+`
		} ELSE { [] };
		RETURN $completed;
		COMMIT TRANSACTION;`,
		map[string]any{
			"user_record": recordID("user", userID), "bundle_version": bundleVersion,
			"identity_version": link.Version, "sign_pub": link.SignPub, "enc_pub": link.EncPub,
			"rotation_sig": link.RotationSig,
		})
	if err != nil {
		return wrapQueryError("complete rotation", err)
	}
	if len(updated) == 0 {
		return ErrConflict
	}
	return nil
}

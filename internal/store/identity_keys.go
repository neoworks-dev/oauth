package store

import "context"

// IdentityKey is one version of a user's identity key pair. Version 1 has no
// rotation signature.
type IdentityKey struct {
	Version     uint32  `json:"version"`
	SignPub     string  `json:"signPub"`
	EncPub      string  `json:"encPub"`
	RotationSig *string `json:"rotationSig"`
}

type identityKeyRow struct {
	Version     uint32  `json:"version"`
	SignPub     string  `json:"sign_pub"`
	EncPub      string  `json:"enc_pub"`
	RotationSig *string `json:"rotation_sig"`
}

// LatestIdentityKey is the newest identity version in the user's history.
func (store *Store) LatestIdentityKey(ctx context.Context, userID string) (*IdentityKey, error) {
	row, err := firstRow[identityKeyRow](ctx, store,
		"SELECT version, sign_pub, enc_pub, rotation_sig FROM identity_key WHERE user = $user ORDER BY version DESC LIMIT 1",
		map[string]any{"user": recordID("user", userID)})
	if err != nil {
		return nil, err
	}
	return &IdentityKey{Version: row.Version, SignPub: row.SignPub, EncPub: row.EncPub, RotationSig: row.RotationSig}, nil
}

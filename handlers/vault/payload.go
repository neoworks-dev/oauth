package vault

import (
	"errors"
	"time"

	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/wire"
)

const (
	publicKeyBytes  = 32
	signatureBytes  = 64
	sealOverhead    = 48
	nodeKeyBytes    = 32
	maxBlobTextSize = 4096
)

var errInvalidPayload = errors.New("invalid payload")

// facetPayload is one encrypted facet of a node on the wire.
type facetPayload struct {
	Facet      uint32 `json:"facet"`
	Ciphertext string `json:"ciphertext"`
}

// nodePayload is a node as the client sends it (contract section 4).
type nodePayload struct {
	ID         string         `json:"id"`
	ParentID   *string        `json:"parentId"`
	OwnerID    string         `json:"ownerId"`
	Collection string         `json:"collection"`
	Kind       string         `json:"kind"`
	Epoch      uint32         `json:"epoch"`
	WrappedKey *string        `json:"wrappedKey"`
	Content    []facetPayload `json:"content"`
	Blob       map[string]any `json:"blob"`
	Deleted    bool           `json:"deleted"`
	BaseSeq    uint64         `json:"baseSeq"`
	AuthorType string         `json:"authorType"`
	AuthorID   string         `json:"authorId"`
	CertID     *string        `json:"certId"`
	Signature  string         `json:"signature"`
}

// grantPayload is an access grant as the client sends it (contract section 5).
// Signature is the signature of the grant's access log entry, which sits at
// LogIndex and chains to PrevHash (contract amendment 1).
type grantPayload struct {
	NodeID        string   `json:"nodeId"`
	PrincipalType string   `json:"principalType"`
	PrincipalID   string   `json:"principalId"`
	Role          string   `json:"role"`
	Facets        []uint32 `json:"facets"`
	Epoch         uint32   `json:"epoch"`
	WrappedKeys   string   `json:"wrappedKeys"`
	GrantedByType string   `json:"grantedByType"`
	GrantedByID   string   `json:"grantedById"`
	CertID        *string  `json:"certId"`
	Signature     string   `json:"signature"`
	LogIndex      uint64   `json:"logIndex"`
	PrevHash      string   `json:"prevHash"`
}

// bundlePayload is the key bundle as the client sends it.
type bundlePayload struct {
	Version         uint32 `json:"version"`
	AmkPassword     string `json:"amkPassword"`
	AmkRecovery     string `json:"amkRecovery"`
	IdentityPrivate string `json:"identityPrivate"`
	EncPub          string `json:"encPub"`
	SignPub         string `json:"signPub"`
	SelfSig         string `json:"selfSig"`
	// Previous accompanies a full rotation: the replaced identity, wrapped under
	// the new AMK, until every key is rewrapped.
	Previous *previousIdentityPayload `json:"previous"`
}

type previousIdentityPayload struct {
	IdentityPrivate string `json:"identityPrivate"`
	EncPub          string `json:"encPub"`
	SignPub         string `json:"signPub"`
}

// decodeSized decodes base64url text that must be exactly size bytes.
func decodeSized(text string, size int) ([]byte, error) {
	decoded, err := wire.DecodeBase64URL(text)
	if err != nil || len(decoded) != size {
		return nil, errInvalidPayload
	}
	return decoded, nil
}

// decodeBounded decodes base64url text of between 1 and maxSize bytes.
func decodeBounded(text string, maxSize int) ([]byte, error) {
	decoded, err := wire.DecodeBase64URL(text)
	if err != nil || len(decoded) == 0 || len(decoded) > maxSize {
		return nil, errInvalidPayload
	}
	return decoded, nil
}

// verifiedIdentity checks the bundle's public keys and selfSig and returns the
// decoded signing key.
func verifiedIdentity(userID string, bundle bundlePayload) ([]byte, error) {
	encPub, err := decodeSized(bundle.EncPub, publicKeyBytes)
	if err != nil {
		return nil, err
	}
	signPub, err := decodeSized(bundle.SignPub, publicKeyBytes)
	if err != nil {
		return nil, err
	}
	selfSig, err := decodeSized(bundle.SelfSig, signatureBytes)
	if err != nil {
		return nil, err
	}
	if !wire.Verify(signPub, wire.IdentityMessage(userID, encPub, signPub), selfSig) {
		return nil, errInvalidPayload
	}
	return signPub, nil
}

// checkOpaqueBundleFields validates the wrapped values the server cannot open.
func checkOpaqueBundleFields(bundle bundlePayload) error {
	for _, field := range []string{bundle.AmkPassword, bundle.AmkRecovery, bundle.IdentityPrivate} {
		if _, err := decodeBounded(field, maxBlobTextSize); err != nil {
			return err
		}
	}
	return nil
}

// wrappedKeyCount is how many 32 byte keys a grant seals: one for a whole node,
// one per facet otherwise.
func wrappedKeyCount(facets []uint32) int {
	if len(facets) == 0 {
		return 1
	}
	return len(facets)
}

// verifiedGrantEntry checks the structure of a grant's sealed keys and the
// granter's signature over the grant's access log entry, and returns the
// stored form of the grant with its entry hash.
func verifiedGrantEntry(grant grantPayload, signPub []byte, now time.Time) (store.AccessGrant, error) {
	wrappedKeys, err := decodeSized(grant.WrappedKeys, sealOverhead+nodeKeyBytes*wrappedKeyCount(grant.Facets))
	if err != nil {
		return store.AccessGrant{}, err
	}
	signature, err := decodeSized(grant.Signature, signatureBytes)
	if err != nil {
		return store.AccessGrant{}, err
	}
	prevHash, err := decodeSized(grant.PrevHash, len(wire.GenesisPrevHash))
	if err != nil {
		return store.AccessGrant{}, err
	}
	entry := grant.entryMessage(prevHash, wire.Hash(wrappedKeys))
	entryBytes := entry.Bytes()
	if !wire.Verify(signPub, entryBytes, signature) {
		return store.AccessGrant{}, errInvalidPayload
	}
	stored := grant.toStored(now)
	stored.WrappedKeysHash = wire.EncodeBase64URL(entry.WrappedKeysHash)
	stored.EntryHash = wire.EncodeBase64URL(wire.Hash(entryBytes))
	return stored, nil
}

func (grant grantPayload) entryMessage(prevHash, wrappedKeysHash []byte) wire.AccessEntryMessage {
	entry := wire.AccessEntryMessage{
		NodeID:          grant.NodeID,
		Index:           grant.LogIndex,
		PrevHash:        prevHash,
		Action:          "grant",
		PrincipalType:   grant.PrincipalType,
		PrincipalID:     grant.PrincipalID,
		Role:            grant.Role,
		Facets:          grant.Facets,
		Epoch:           grant.Epoch,
		WrappedKeysHash: wrappedKeysHash,
		ActorType:       grant.GrantedByType,
		ActorID:         grant.GrantedByID,
	}
	if grant.CertID != nil {
		entry.CertID = *grant.CertID
	}
	return entry
}

func (grant grantPayload) toStored(now time.Time) store.AccessGrant {
	stored := store.AccessGrant{
		NodeID:        grant.NodeID,
		PrincipalType: grant.PrincipalType,
		PrincipalID:   grant.PrincipalID,
		Role:          grant.Role,
		Facets:        grant.Facets,
		Epoch:         grant.Epoch,
		WrappedKeys:   grant.WrappedKeys,
		GrantedByType: grant.GrantedByType,
		GrantedByID:   grant.GrantedByID,
		Signature:     grant.Signature,
		LogIndex:      grant.LogIndex,
		PrevHash:      grant.PrevHash,
		CreatedAt:     now,
	}
	if grant.CertID != nil {
		stored.CertID = *grant.CertID
	}
	return stored
}

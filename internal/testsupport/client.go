package testsupport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/oauth/internal/wire"
	"golang.org/x/crypto/nacl/box"
)

// TestCollections are the collections tests ask for, each published as a node
// schema by PublishCollections.
var TestCollections = []string{"@neoworks/calendar", "@neoworks/contacts", "@neoworks/photos", "@neoworks/files"}

// Account is a user as the browser would create it: random keys, and the root
// node of each test collection with the owner's grant, sent at the first
// consent that asks for the collection.
type Account struct {
	UserID   string
	Email    string
	AuthKey  []byte
	DeviceID string
	EncPub   *[32]byte
	EncSec   *[32]byte
	SignPub  ed25519.PublicKey
	SignSec  ed25519.PrivateKey
	RootIDs  map[string]string
	RootKeys map[string][]byte
	// LogHeads is the access log head per node as the server holds it;
	// builtEntries are the entries Grant signed since the last CommitGrants.
	LogHeads     map[string]LogHead
	builtEntries map[string]LogHead
}

// LogHead is the newest entry of a node's access log.
type LogHead struct {
	Index uint64
	Hash  []byte
}

func randomBytes(size int) []byte {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer)
	return buffer
}

func NewAccount(email string) *Account {
	encPub, encSec, _ := box.GenerateKey(rand.Reader)
	signPub, signSec, _ := ed25519.GenerateKey(rand.Reader)
	account := &Account{
		UserID: uuid.NewString(), Email: email, AuthKey: randomBytes(32), DeviceID: uuid.NewString(),
		EncPub: encPub, EncSec: encSec, SignPub: signPub, SignSec: signSec,
		RootIDs: map[string]string{}, RootKeys: map[string][]byte{},
		LogHeads: map[string]LogHead{}, builtEntries: map[string]LogHead{},
	}
	for _, collection := range TestCollections {
		account.RootIDs[collection] = uuid.NewString()
		account.RootKeys[collection] = randomBytes(32)
	}
	return account
}

func (account *Account) AuthKeyText() string {
	return wire.EncodeBase64URL(account.AuthKey)
}

// Seal seals plaintext to a public key like crypto_box_seal.
func Seal(publicKey *[32]byte, plaintext []byte) []byte {
	sealed, _ := box.SealAnonymous(nil, plaintext, publicKey, rand.Reader)
	return sealed
}

func (account *Account) rootNode(collection string) map[string]any {
	return map[string]any{
		"id": account.RootIDs[collection], "parentId": nil, "ownerId": account.UserID,
		"collection": collection, "kind": "root", "epoch": 1, "wrappedKey": nil,
		"content": "", "blob": nil, "targetId": nil, "targetRole": nil, "deleted": false, "baseSeq": 0,
		"authorType": "user", "authorId": account.UserID, "certId": nil,
		"signature": wire.EncodeBase64URL(ed25519.Sign(account.SignSec, randomBytes(16))),
	}
}

// NewRoots returns, for each of the collections not among stored (the
// collections the server already holds the account's roots in), the root and
// the owner's genesis grant on it as a consent carries them. Their entries
// become the log heads, so install grants built next chain after them.
func (account *Account) NewRoots(collections, stored []string) []map[string]any {
	roots := []map[string]any{}
	for _, collection := range collections {
		if slices.Contains(stored, collection) || account.RootIDs[collection] == "" {
			continue
		}
		rootID := account.RootIDs[collection]
		delete(account.LogHeads, rootID)
		grant := account.Grant(rootID, "user", account.UserID, "write", 1, nil, account.EncPub, "")
		roots = append(roots, map[string]any{"node": account.rootNode(collection), "grant": grant})
	}
	account.CommitGrants()
	return roots
}

// Grant builds a signed access grant for a node key whose log entry extends
// the node's head in LogHeads.
func (account *Account) Grant(nodeID, principalType, principalID, role string, epoch uint32, facets []uint32, sealedTo *[32]byte, certID string) map[string]any {
	keyCount := 1
	if len(facets) > 0 {
		keyCount = len(facets)
	}
	wrapped := Seal(sealedTo, randomBytes(32*keyCount))
	entry := account.nextEntry(nodeID)
	entry.PrincipalType, entry.PrincipalID, entry.Role = principalType, principalID, role
	entry.Facets, entry.Epoch, entry.WrappedKeysHash, entry.CertID = facets, epoch, wire.Hash(wrapped), certID
	entryBytes := entry.Bytes()
	account.builtEntries[nodeID] = LogHead{Index: entry.Index, Hash: wire.Hash(entryBytes)}
	grant := map[string]any{
		"nodeId": nodeID, "principalType": principalType, "principalId": principalID, "role": role,
		"facets": nil, "epoch": epoch, "wrappedKeys": wire.EncodeBase64URL(wrapped),
		"grantedByType": "user", "grantedById": account.UserID, "certId": nil,
		"signature": wire.EncodeBase64URL(ed25519.Sign(account.SignSec, entryBytes)),
		"logIndex":  entry.Index, "prevHash": wire.EncodeBase64URL(entry.PrevHash),
	}
	if facets != nil {
		grant["facets"] = facets
	}
	if certID != "" {
		grant["certId"] = certID
	}
	return grant
}

// nextEntry is a grant entry by the account at the position after the node's head.
func (account *Account) nextEntry(nodeID string) wire.AccessEntryMessage {
	entry := wire.AccessEntryMessage{
		NodeID: nodeID, PrevHash: wire.GenesisPrevHash, Action: "grant", ActorType: "user", ActorID: account.UserID,
	}
	head, found := account.LogHeads[nodeID]
	if found {
		entry.Index, entry.PrevHash = head.Index+1, head.Hash
	}
	return entry
}

// CommitGrants records the entries Grant built as the new log heads, once the
// server accepted them.
func (account *Account) CommitGrants() {
	for nodeID, head := range account.builtEntries {
		account.LogHeads[nodeID] = head
	}
	account.builtEntries = map[string]LogHead{}
}

// SelfSignature signs the identity public keys.
func (account *Account) SelfSignature() string {
	message := wire.IdentityMessage(account.UserID, account.EncPub[:], account.SignPub)
	return wire.EncodeBase64URL(ed25519.Sign(account.SignSec, message))
}

// Bundle is the key bundle payload for a bundle version.
func (account *Account) Bundle(version uint32) map[string]any {
	return map[string]any{
		"version": version, "amkPassword": wire.EncodeBase64URL(randomBytes(72)),
		"amkRecovery": wire.EncodeBase64URL(randomBytes(72)), "identityPrivate": wire.EncodeBase64URL(randomBytes(144)),
		"encPub": wire.EncodeBase64URL(account.EncPub[:]), "signPub": wire.EncodeBase64URL(account.SignPub),
		"selfSig": account.SelfSignature(),
	}
}

// PwhashParams is the per-account parameter set a signup sends.
func PwhashParams() map[string]any {
	return map[string]any{"salt": wire.EncodeBase64URL(randomBytes(16)), "ops": 3, "mem": 67108864}
}

// SignupRequest is a complete, valid signup body.
func (account *Account) SignupRequest() map[string]any {
	return map[string]any{
		"email": account.Email, "firstName": "Test", "lastName": "User", "userId": account.UserID,
		"authKey": account.AuthKeyText(), "pwhash": PwhashParams(), "bundle": account.Bundle(1),
		"device": map[string]any{"id": account.DeviceID, "name": "Test browser"},
	}
}

// Certificate builds a signed delegation certificate.
type Certificate struct {
	CertID    string
	Bytes     string
	Signature string
}

// CertificateParams selects the contents of a test certificate.
type CertificateParams struct {
	InstallID      string
	ClientID       string
	InstallEncPub  string
	InstallSignPub string
	Scopes         []string
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

func (account *Account) Certificate(params CertificateParams) Certificate {
	certID := uuid.NewString()
	document, _ := json.Marshal(map[string]any{
		"v": 1, "certId": certID, "userId": account.UserID, "installId": params.InstallID,
		"clientId": params.ClientID, "installEncPub": params.InstallEncPub, "installSignPub": params.InstallSignPub,
		"scopes": params.Scopes, "issuedAt": params.IssuedAt.UTC().Format(time.RFC3339),
		"expiresAt": params.ExpiresAt.UTC().Format(time.RFC3339),
	})
	signature := ed25519.Sign(account.SignSec, wire.DelegationMessage(document))
	return Certificate{CertID: certID, Bytes: wire.EncodeBase64URL(document), Signature: wire.EncodeBase64URL(signature)}
}

// Install is an app installation's keys.
type Install struct {
	ID      string
	EncPub  *[32]byte
	SignPub ed25519.PublicKey
}

func NewInstall() Install {
	encPub, _, _ := box.GenerateKey(rand.Reader)
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)
	return Install{ID: uuid.NewString(), EncPub: encPub, SignPub: signPub}
}

// PasswordChange is the body of a password change or reset for new password material.
func (account *Account) PasswordChange(expectedVersion uint32, newAuthKey []byte) map[string]any {
	return map[string]any{
		"newAuthKey": wire.EncodeBase64URL(newAuthKey), "pwhash": PwhashParams(),
		"amkPassword": wire.EncodeBase64URL(randomBytes(72)), "expectedVersion": expectedVersion,
	}
}

// RotationRequest is the body of a rotation to bundle version expectedVersion+1.
func (account *Account) RotationRequest(expectedVersion uint32, newAuthKey []byte) map[string]any {
	bundle := account.Bundle(expectedVersion + 1)
	request := account.PasswordChange(expectedVersion, newAuthKey)
	request["amkPassword"] = bundle["amkPassword"]
	request["currentAuthKey"] = account.AuthKeyText()
	request["bundle"] = bundle
	return request
}

// WithNewIdentity is the same user with a freshly generated identity, as after
// a full rotation.
func (account *Account) WithNewIdentity() *Account {
	rotated := *account
	rotated.EncPub, rotated.EncSec, _ = box.GenerateKey(rand.Reader)
	rotated.SignPub, rotated.SignSec, _ = ed25519.GenerateKey(rand.Reader)
	return &rotated
}

// FullRotationRequest rotates from this account's identity to next's. The
// bundle carries the replaced identity, which the server keeps until the
// rotation is completed.
func (account *Account) FullRotationRequest(next *Account, expectedVersion uint32, newAuthKey []byte) map[string]any {
	request := next.RotationRequest(expectedVersion, newAuthKey)
	request["currentAuthKey"] = account.AuthKeyText()
	request["bundle"].(map[string]any)["previous"] = map[string]any{
		"identityPrivate": wire.EncodeBase64URL(randomBytes(144)),
		"encPub":          wire.EncodeBase64URL(account.EncPub[:]),
		"signPub":         wire.EncodeBase64URL(account.SignPub),
	}
	return request
}

// RotationSignature is this account's identity endorsing next's identity as
// the given history version.
func (account *Account) RotationSignature(next *Account, identityVersion uint32) string {
	message := wire.IdentityRotationMessage(account.UserID, identityVersion, next.SignPub, next.EncPub[:])
	return wire.EncodeBase64URL(ed25519.Sign(account.SignSec, message))
}

// RandomKey returns 32 random bytes, for an authKey.
func RandomKey() []byte {
	return randomBytes(32)
}

// Package signing loads the ES256 key that signs access tokens and publishes it
// as a JWKS document.
package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

const KeyID = "neoworks-auth-v1"

type KeyManager struct {
	privateKey *ecdsa.PrivateKey
}

// NewKeyManager prefers the AUTH_PRIVATE_KEY environment variable, then the
// key file. A missing key file is generated, which is meant for development.
func NewKeyManager(keyPath string) (*KeyManager, error) {
	pemText := os.Getenv("AUTH_PRIVATE_KEY")
	if pemText != "" {
		return keyManagerFromPEM([]byte(pemText))
	}
	_, statErr := os.Stat(keyPath)
	if errors.Is(statErr, os.ErrNotExist) {
		return generateKeyFile(keyPath)
	}
	fileBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return keyManagerFromPEM(fileBytes)
}

func keyManagerFromPEM(pemBytes []byte) (*KeyManager, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("signing key: no PEM block")
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &KeyManager{privateKey: privateKey}, nil
}

func generateKeyFile(keyPath string) (*KeyManager, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err != nil {
		return nil, err
	}
	return &KeyManager{privateKey: privateKey}, nil
}

// NewKeyManagerFromKey wraps an existing key, for tests.
func NewKeyManagerFromKey(privateKey *ecdsa.PrivateKey) *KeyManager {
	return &KeyManager{privateKey: privateKey}
}

func (manager *KeyManager) PrivateKey() *ecdsa.PrivateKey {
	return manager.privateKey
}

// DerivedSecret returns stable key material bound to the signing key, for
// purposes that need a server secret without extra configuration.
func (manager *KeyManager) DerivedSecret(purpose string) []byte {
	der, err := x509.MarshalECPrivateKey(manager.privateKey)
	if err != nil {
		panic(err)
	}
	return deriveSecret(der, purpose)
}

type jsonWebKey struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
}

// JWKSJSON renders the public key set served at /.well-known/jwks.json.
func (manager *KeyManager) JWKSJSON() ([]byte, error) {
	publicKey := manager.privateKey.PublicKey
	coordinateSize := (publicKey.Curve.Params().BitSize + 7) / 8
	key := jsonWebKey{
		KeyType:   "EC",
		Curve:     "P-256",
		X:         base64.RawURLEncoding.EncodeToString(publicKey.X.FillBytes(make([]byte, coordinateSize))),
		Y:         base64.RawURLEncoding.EncodeToString(publicKey.Y.FillBytes(make([]byte, coordinateSize))),
		KeyID:     KeyID,
		Algorithm: "ES256",
		Use:       "sig",
	}
	return json.Marshal(map[string][]jsonWebKey{"keys": {key}})
}

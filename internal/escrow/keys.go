package escrow

import (
	"context"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

const (
	serviceKeyContext = "escrow-service-key"
	boxKeySize        = 32
	devSeedText       = "neoworks-escrow-development-key-v1"
)

// ServiceKey is the X25519 keypair clients seal AMKs to. Its public half is
// pinned in the vault build.
type ServiceKey struct {
	Public [boxKeySize]byte
	Secret [boxKeySize]byte
}

// DevServiceKey derives the fixed keypair used by development setups, so the
// public key pinned in the vault build matches without any provisioning.
func DevServiceKey() ServiceKey {
	seed := blake2b.Sum256([]byte(devSeedText))
	return serviceKeyFromSecret(seed)
}

func serviceKeyFromSecret(secret [boxKeySize]byte) ServiceKey {
	var key ServiceKey
	key.Secret = secret
	public, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	copy(key.Public[:], public)
	return key
}

// LoadOrCreateServiceKey returns the stored keypair, generating and storing it
// (secret encrypted by the KMS) on first start. A fixed development key can be
// requested instead.
func LoadOrCreateServiceKey(ctx context.Context, repository Repository, kms KMS, useDevKey bool) (ServiceKey, error) {
	if useDevKey {
		return DevServiceKey(), nil
	}
	publicKey, sealedSecret, err := repository.GetServiceKey(ctx)
	if errors.Is(err, ErrNotFound) {
		return createServiceKey(ctx, repository, kms)
	}
	if err != nil {
		return ServiceKey{}, err
	}
	secret, err := kms.Decrypt(ctx, sealedSecret, []byte(serviceKeyContext))
	if err != nil || len(secret) != boxKeySize {
		return ServiceKey{}, errors.New("escrow service key cannot be opened with this KMS")
	}
	var key ServiceKey
	copy(key.Secret[:], secret)
	copy(key.Public[:], publicKey)
	return key, nil
}

func createServiceKey(ctx context.Context, repository Repository, kms KMS) (ServiceKey, error) {
	var secret [boxKeySize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return ServiceKey{}, err
	}
	key := serviceKeyFromSecret(secret)
	sealed, err := kms.Encrypt(ctx, key.Secret[:], []byte(serviceKeyContext))
	if err != nil {
		return ServiceKey{}, err
	}
	if err := repository.PutServiceKey(ctx, key.Public[:], sealed); err != nil {
		return ServiceKey{}, err
	}
	return key, nil
}

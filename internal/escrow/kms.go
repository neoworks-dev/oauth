// Package escrow is the opt-in key escrow service. It holds each opted-in
// user's AMK encrypted under a KMS key, and releases it, sealed to a fresh
// device key, only after a waiting period that every device can cancel.
package escrow

import (
	"context"
	"crypto/rand"
	"errors"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

// KMS encrypts and decrypts small secrets under a key that never leaves it.
// Production backs this with a managed KMS or HSM; development uses FileKMS.
type KMS interface {
	Encrypt(ctx context.Context, plaintext, context []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext, context []byte) ([]byte, error)
}

// FileKMS is a development stand-in that keeps the key in a file.
type FileKMS struct {
	key []byte
}

var errBadKeyFile = errors.New("kms key file must hold 32 bytes")

// LoadFileKMS reads the key file. With create set, a missing file is generated.
func LoadFileKMS(path string, create bool) (*FileKMS, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		return createKeyFile(path)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, errBadKeyFile
	}
	return &FileKMS{key: key}, nil
}

func createKeyFile(path string) (*FileKMS, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return &FileKMS{key: key}, nil
}

// NewMemoryKMS returns a KMS with a random key held in memory, for tests.
func NewMemoryKMS() *FileKMS {
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(key)
	return &FileKMS{key: key}
}

func (kms *FileKMS) Encrypt(_ context.Context, plaintext, binding []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kms.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, binding), nil
}

func (kms *FileKMS) Decrypt(_ context.Context, ciphertext, binding []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kms.key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("kms ciphertext too short")
	}
	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	return aead.Open(nil, nonce, ciphertext[chacha20poly1305.NonceSizeX:], binding)
}

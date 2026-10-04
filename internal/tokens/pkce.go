package tokens

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

var (
	ErrInvalidVerifier   = errors.New("code verifier does not match challenge")
	ErrUnsupportedMethod = errors.New("unsupported code challenge method")
)

// VerifyPKCE accepts only S256. The plain method is rejected.
func VerifyPKCE(verifier, challenge, method string) error {
	if method != "S256" {
		return ErrUnsupportedMethod
	}
	digest := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrInvalidVerifier
	}
	return nil
}

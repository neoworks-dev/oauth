package oauth

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/ids"
	"github.com/neoworks/oauth/internal/wire"
)

const (
	publicKeySize  = 32
	maxInstallName = 80
)

var errInstallIncomplete = errors.New("install_id, install_enc_pub and install_sign_pub must be sent together")

// parseInstallRequest reads the install parameters of an authorization request.
// It returns nil when none were sent.
func parseInstallRequest(installID, encPub, signPub, name string) (*cache.InstallRequest, error) {
	if installID == "" && encPub == "" && signPub == "" {
		return nil, nil
	}
	if installID == "" || encPub == "" || signPub == "" {
		return nil, errInstallIncomplete
	}
	if !ids.IsLowercaseUUIDv4(installID) {
		return nil, errors.New("install_id must be a lowercase UUIDv4")
	}
	for _, publicKey := range []string{encPub, signPub} {
		if !isPublicKey(publicKey) {
			return nil, errors.New("install public keys must be 32 bytes, base64url without padding")
		}
	}
	return &cache.InstallRequest{
		ID:      installID,
		EncPub:  encPub,
		SignPub: signPub,
		Name:    cleanInstallName(name),
	}, nil
}

func isPublicKey(encoded string) bool {
	decoded, err := wire.DecodeBase64URL(encoded)
	return err == nil && len(decoded) == publicKeySize
}

func cleanInstallName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "App"
	}
	if utf8.RuneCountInString(name) > maxInstallName {
		return string([]rune(name)[:maxInstallName])
	}
	return name
}

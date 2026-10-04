package signing

import (
	"crypto/hmac"
	"crypto/sha256"
)

func deriveSecret(keyMaterial []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, keyMaterial)
	mac.Write([]byte("neoworks-derived-secret-v1:" + purpose))
	return mac.Sum(nil)
}

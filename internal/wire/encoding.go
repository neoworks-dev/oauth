// Package wire holds the byte-level encodings shared with the clients: base64url
// and the tlv framing that all signatures and AAD are built from.
package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2b"
)

func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func DecodeBase64URL(text string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(text)
}

// TLV frames a context string and its fields: utf8(context) 0x00, then each
// field as u32be(length) followed by its bytes.
func TLV(context string, fields ...[]byte) []byte {
	framed := append([]byte(context), 0x00)
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed
}

func String(text string) []byte {
	return []byte(text)
}

func U8(value uint8) []byte {
	return []byte{value}
}

func U32(value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return encoded[:]
}

func U64(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func Bool(value bool) []byte {
	if value {
		return U8(1)
	}
	return U8(0)
}

// Hash is H(x): BLAKE2b with a 32 byte digest, the libsodium generichash default.
func Hash(data []byte) []byte {
	digest := blake2b.Sum256(data)
	return digest[:]
}

// FacetsCSV renders a facet list for signatures. A nil list, meaning the whole
// node, renders as the empty string.
func FacetsCSV(facets []uint32) string {
	parts := make([]string, 0, len(facets))
	for _, facet := range facets {
		parts = append(parts, strconv.FormatUint(uint64(facet), 10))
	}
	return strings.Join(parts, ",")
}

// Verify checks a detached Ed25519 signature.
func Verify(signPub, message, signature []byte) bool {
	if len(signPub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(signPub), message, signature)
}

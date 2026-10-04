package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const vectorsPath = "../../../../packages/libneoworks/test-vectors/v1.json"

type rotationVector struct {
	UserID   string `json:"userId"`
	Versions []struct {
		SignPubHex     string `json:"signPubHex"`
		EncPubHex      string `json:"encPubHex"`
		RotationSigHex string `json:"rotationSigHex"`
	} `json:"versions"`
	MessageToVersion2Hex string `json:"rotationMessageToVersion2Hex"`
	MessageToVersion3Hex string `json:"rotationMessageToVersion3Hex"`
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func TestIdentityRotationMessageMatchesTheContractVector(t *testing.T) {
	contents, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Skip("libneoworks test vectors are not checked out next to this repository")
	}
	var vectors struct {
		IdentityHistory rotationVector `json:"identityHistory"`
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	vector := vectors.IdentityHistory
	messages := []string{vector.MessageToVersion2Hex, vector.MessageToVersion3Hex}
	for index, expected := range messages {
		version := uint32(index + 2)
		current := vector.Versions[index+1]
		message := IdentityRotationMessage(vector.UserID, version, mustHex(t, current.SignPubHex), mustHex(t, current.EncPubHex))
		if hex.EncodeToString(message) != expected {
			t.Fatalf("rotation message for version %d differs from the vector", version)
		}
		previousSignPub := ed25519.PublicKey(mustHex(t, vector.Versions[index].SignPubHex))
		if !Verify(previousSignPub, message, mustHex(t, current.RotationSigHex)) {
			t.Fatalf("rotation signature for version %d does not verify", version)
		}
	}
}

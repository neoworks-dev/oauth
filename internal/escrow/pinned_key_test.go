package escrow

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// The vault build pins the development service key; it must match the key the
// service derives in development mode.
func TestVaultPinsTheDevelopmentServiceKey(t *testing.T) {
	source, err := os.ReadFile("../../handlers/vault/static/escrow-key.js")
	if err != nil {
		t.Fatal(err)
	}
	devKey := DevServiceKey()
	want := base64.RawURLEncoding.EncodeToString(devKey.Public[:])
	if !strings.Contains(string(source), `"`+want+`"`) {
		t.Fatalf("escrow-key.js must pin %s", want)
	}
}

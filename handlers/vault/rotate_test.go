package vault

import (
	"testing"

	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/wire"
)

func TestRotationInstallsTheNextBundleVersion(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("rotate"))
	vault.signUp(t, account)
	newKey := testsupport.RandomKey()

	rotated := vault.browser.Do("POST", "/vault/rotate", account.RotationRequest(1, newKey), nil)
	if rotated.Status != 200 || rotated.Body["version"] != float64(2) {
		t.Fatalf("rotate: %d %s", rotated.Status, rotated.Raw)
	}
	bundle := vault.browser.Do("GET", "/vault/bundle", nil, nil)
	if bundle.Body["version"] != float64(2) {
		t.Fatalf("bundle after rotation: %s", bundle.Raw)
	}
	replayed := account.RotationRequest(1, testsupport.RandomKey())
	replayed["currentAuthKey"] = wire.EncodeBase64URL(newKey)
	if replay := vault.browser.Do("POST", "/vault/rotate", replayed, nil); replay.Status != 409 {
		t.Fatalf("an older version must be rejected, got %d", replay.Status)
	}
	other := testsupport.NewBrowser(t, vault.server.Router())
	login := other.Do("POST", "/vault/login", map[string]any{"email": account.Email, "authKey": wire.EncodeBase64URL(newKey), "deviceId": account.DeviceID}, nil)
	if login.Status != 200 {
		t.Fatalf("login with the new authKey: %d", login.Status)
	}
}

func TestRotationRejectsBadRequests(t *testing.T) {
	cases := map[string]func(request map[string]any){
		"wrong current key": func(request map[string]any) {
			request["currentAuthKey"] = wire.EncodeBase64URL(testsupport.RandomKey())
		},
		"version skipped": func(request map[string]any) {
			request["bundle"].(map[string]any)["version"] = 5
		},
		"bundle not signed by its own identity": func(request map[string]any) {
			request["bundle"].(map[string]any)["selfSig"] = wire.EncodeBase64URL(make([]byte, 64))
		},
		"password wrap differs from the bundle": func(request map[string]any) {
			request["amkPassword"] = wire.EncodeBase64URL(make([]byte, 72))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			vault := newTestVault(t)
			account := testsupport.NewAccount(uniqueEmail("badrotate"))
			vault.signUp(t, account)
			request := account.RotationRequest(1, testsupport.RandomKey())
			mutate(request)
			response := vault.browser.Do("POST", "/vault/rotate", request, nil)
			if response.Status != 400 && response.Status != 401 {
				t.Fatalf("status %d (%s)", response.Status, response.Raw)
			}
			bundle := vault.browser.Do("GET", "/vault/bundle", nil, nil)
			if bundle.Body["version"] != float64(1) {
				t.Fatalf("a rejected rotation must change nothing: %s", bundle.Raw)
			}
		})
	}
}

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

func rotatedVault(t *testing.T) (*testVault, *testsupport.Account, *testsupport.Account, []byte) {
	t.Helper()
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("fullrotate"))
	vault.signUp(t, account)
	next := account.WithNewIdentity()
	newKey := testsupport.RandomKey()
	rotated := vault.browser.Do("POST", "/vault/rotate", account.FullRotationRequest(next, 1, newKey), nil)
	if rotated.Status != 200 {
		t.Fatalf("full rotation: %d %s", rotated.Status, rotated.Raw)
	}
	return vault, account, next, newKey
}

func TestFullRotationKeepsThePreviousIdentityUntilCompleted(t *testing.T) {
	vault, account, next, newKey := rotatedVault(t)
	bundle := vault.browser.Do("GET", "/vault/bundle", nil, nil)
	previous, _ := bundle.Body["previous"].(map[string]any)
	if previous["encPub"] != wire.EncodeBase64URL(account.EncPub[:]) || bundle.Body["encPub"] != wire.EncodeBase64URL(next.EncPub[:]) {
		t.Fatalf("bundle after a full rotation: %s", bundle.Raw)
	}

	complete := map[string]any{"currentAuthKey": wire.EncodeBase64URL(newKey), "version": 2}
	if wrong := vault.browser.Do("POST", "/vault/rotate/complete", map[string]any{"currentAuthKey": account.AuthKeyText(), "version": 2}, nil); wrong.Status != 401 {
		t.Fatalf("completing with the old authKey: %d, want 401", wrong.Status)
	}
	if stale := vault.browser.Do("POST", "/vault/rotate/complete", map[string]any{"currentAuthKey": wire.EncodeBase64URL(newKey), "version": 1}, nil); stale.Status != 409 {
		t.Fatalf("completing a stale version: %d, want 409", stale.Status)
	}
	if done := vault.browser.Do("POST", "/vault/rotate/complete", complete, nil); done.Status != 200 {
		t.Fatalf("complete: %d %s", done.Status, done.Raw)
	}
	after := vault.browser.Do("GET", "/vault/bundle", nil, nil)
	if after.Body["previous"] != nil {
		t.Fatalf("the previous identity must be gone after completing: %s", after.Raw)
	}
}

func TestFullRotationCannotStartWhileAnotherIsUnfinished(t *testing.T) {
	vault, _, next, newKey := rotatedVault(t)
	again := next.WithNewIdentity()
	request := next.FullRotationRequest(again, 2, testsupport.RandomKey())
	request["currentAuthKey"] = wire.EncodeBase64URL(newKey)
	if response := vault.browser.Do("POST", "/vault/rotate", request, nil); response.Status != 409 {
		t.Fatalf("second full rotation: %d %s, want 409", response.Status, response.Raw)
	}
}

func TestRotationRefusesAMisplacedPreviousIdentity(t *testing.T) {
	cases := map[string]func(request map[string]any, account *testsupport.Account){
		"identity change without the previous identity": func(request map[string]any, _ *testsupport.Account) {
			delete(request["bundle"].(map[string]any), "previous")
		},
		"previous identity that is not the current one": func(request map[string]any, _ *testsupport.Account) {
			request["bundle"].(map[string]any)["previous"].(map[string]any)["encPub"] = wire.EncodeBase64URL(make([]byte, 32))
		},
		"light rotation carrying a previous identity": func(request map[string]any, account *testsupport.Account) {
			bundle := account.Bundle(2)
			bundle["previous"] = request["bundle"].(map[string]any)["previous"]
			request["bundle"] = bundle
			request["amkPassword"] = bundle["amkPassword"]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			vault := newTestVault(t)
			account := testsupport.NewAccount(uniqueEmail("badprevious"))
			vault.signUp(t, account)
			request := account.FullRotationRequest(account.WithNewIdentity(), 1, testsupport.RandomKey())
			mutate(request, account)
			if response := vault.browser.Do("POST", "/vault/rotate", request, nil); response.Status != 400 {
				t.Fatalf("status %d (%s), want 400", response.Status, response.Raw)
			}
		})
	}
}

package vault

import (
	"context"
	"testing"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"

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

	complete := map[string]any{
		"currentAuthKey": wire.EncodeBase64URL(newKey), "version": 2, "rotationSig": account.RotationSignature(next, 2),
	}
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
	if after.Body["previous"] != nil || after.Body["identityVersion"] != float64(2) {
		t.Fatalf("the previous identity must be gone after completing: %s", after.Raw)
	}
}

func TestCompletingAFullRotationAppendsTheIdentityToTheHistory(t *testing.T) {
	vault, account, next, newKey := rotatedVault(t)
	before := vault.browser.Do("GET", "/vault/bundle", nil, nil)
	if before.Body["identityVersion"] != float64(2) {
		t.Fatalf("an unfinished rotation names the version it will become: %s", before.Raw)
	}
	complete := map[string]any{
		"currentAuthKey": wire.EncodeBase64URL(newKey), "version": 2, "rotationSig": account.RotationSignature(next, 2),
	}
	if done := vault.browser.Do("POST", "/vault/rotate/complete", complete, nil); done.Status != 200 {
		t.Fatalf("complete: %d %s", done.Status, done.Raw)
	}
	if again := vault.browser.Do("POST", "/vault/rotate/complete", complete, nil); again.Status != 200 {
		t.Fatalf("completing twice: %d %s", again.Status, again.Raw)
	}

	var keys []struct {
		Version     int        `json:"version"`
		SignPub     string     `json:"sign_pub"`
		RotationSig *string    `json:"rotation_sig"`
		RetiredAt   *time.Time `json:"retired_at"`
	}
	results, err := surrealdb.Query[[]struct {
		Version     int        `json:"version"`
		SignPub     string     `json:"sign_pub"`
		RotationSig *string    `json:"rotation_sig"`
		RetiredAt   *time.Time `json:"retired_at"`
	}](context.Background(), testSurreal.DB(),
		"SELECT version, sign_pub, rotation_sig, retired_at FROM identity_key WHERE user = $user ORDER BY version",
		map[string]any{"user": models.NewRecordID("user", account.UserID)})
	if err != nil {
		t.Fatal(err)
	}
	keys = (*results)[0].Result
	if len(keys) != 2 || keys[0].Version != 1 || keys[1].Version != 2 {
		t.Fatalf("history: %+v", keys)
	}
	if keys[0].RetiredAt == nil || keys[0].RotationSig != nil || keys[1].RetiredAt != nil {
		t.Fatalf("retirement: %+v", keys)
	}
	if keys[1].SignPub != wire.EncodeBase64URL(next.SignPub) || keys[1].RotationSig == nil || *keys[1].RotationSig != complete["rotationSig"] {
		t.Fatalf("appended version: %+v", keys[1])
	}
}

func TestCompletingAFullRotationNeedsTheRotationLink(t *testing.T) {
	cases := map[string]func(account, next *testsupport.Account) string{
		"missing":                    func(_, _ *testsupport.Account) string { return "" },
		"signed by the new identity": func(_, next *testsupport.Account) string { return next.RotationSignature(next, 2) },
		"for another version":        func(account, next *testsupport.Account) string { return account.RotationSignature(next, 3) },
		"for another identity": func(account, _ *testsupport.Account) string {
			return account.RotationSignature(account.WithNewIdentity(), 2)
		},
	}
	for name, signature := range cases {
		t.Run(name, func(t *testing.T) {
			vault, account, next, newKey := rotatedVault(t)
			complete := map[string]any{
				"currentAuthKey": wire.EncodeBase64URL(newKey), "version": 2, "rotationSig": signature(account, next),
			}
			if response := vault.browser.Do("POST", "/vault/rotate/complete", complete, nil); response.Status != 400 {
				t.Fatalf("status %d (%s), want 400", response.Status, response.Raw)
			}
			bundle := vault.browser.Do("GET", "/vault/bundle", nil, nil)
			if bundle.Body["previous"] == nil {
				t.Fatalf("a refused completion must keep the previous identity: %s", bundle.Raw)
			}
		})
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

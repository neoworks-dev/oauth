package vault

import (
	"testing"

	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/wire"
)

func TestPasswordChangeNeedsTheCurrentAuthKeyAndTheCurrentVersion(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("change"))
	vault.signUp(t, account)

	newKey := testsupport.RandomKey()
	request := account.PasswordChange(1, newKey)
	request["currentAuthKey"] = wire.EncodeBase64URL(testsupport.RandomKey())
	if wrong := vault.browser.Do("POST", "/vault/password", request, nil); wrong.Status != 401 {
		t.Fatalf("a wrong current key: %d", wrong.Status)
	}
	request["currentAuthKey"] = account.AuthKeyText()
	stale := account.PasswordChange(7, newKey)
	stale["currentAuthKey"] = account.AuthKeyText()
	if conflict := vault.browser.Do("POST", "/vault/password", stale, nil); conflict.Status != 409 {
		t.Fatalf("a stale bundle version: %d", conflict.Status)
	}
	if changed := vault.browser.Do("POST", "/vault/password", request, nil); changed.Status != 200 {
		t.Fatalf("change: %d %s", changed.Status, changed.Raw)
	}

	other := testsupport.NewBrowser(t, vault.server.Router())
	oldLogin := other.Do("POST", "/vault/login", map[string]any{"email": account.Email, "authKey": account.AuthKeyText(), "deviceId": account.DeviceID}, nil)
	if oldLogin.Status != 401 {
		t.Fatalf("the old authKey must stop working, got %d", oldLogin.Status)
	}
	newLogin := other.Do("POST", "/vault/login", map[string]any{"email": account.Email, "authKey": wire.EncodeBase64URL(newKey), "deviceId": account.DeviceID}, nil)
	if newLogin.Status != 200 {
		t.Fatalf("the new authKey must work, got %d %s", newLogin.Status, newLogin.Raw)
	}
}

func TestPasswordChangeNeedsASession(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("anonymous"))
	vault.signUp(t, account)
	anonymous := testsupport.NewBrowser(t, vault.server.Router())
	request := account.PasswordChange(1, testsupport.RandomKey())
	request["currentAuthKey"] = account.AuthKeyText()
	if response := anonymous.Do("POST", "/vault/password", request, nil); response.Status != 401 {
		t.Fatalf("status %d, want 401", response.Status)
	}
}

// forgotCode requests and returns the reset code of an email.
func forgotCode(t *testing.T, browser *testsupport.Browser, email string) string {
	t.Helper()
	sent := browser.Do("POST", "/vault/forgot/send-code", map[string]any{"email": email}, nil)
	if sent.Status != 200 {
		t.Fatalf("forgot send-code: %d %s", sent.Status, sent.Raw)
	}
	code, _ := sent.Body["code"].(string)
	return code
}

func TestForgotPasswordGivesNothingAwayForUnknownEmails(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("forgot"))
	vault.signUp(t, account)
	anonymous := testsupport.NewBrowser(t, vault.server.Router())

	known := anonymous.Do("POST", "/vault/forgot/send-code", map[string]any{"email": account.Email}, nil)
	unknown := anonymous.Do("POST", "/vault/forgot/send-code", map[string]any{"email": uniqueEmail("nobody")}, nil)
	if known.Status != 200 || unknown.Status != 200 || known.Body["sent"] != true || unknown.Body["sent"] != true {
		t.Fatalf("both must look sent: %d %s / %d %s", known.Status, known.Raw, unknown.Status, unknown.Raw)
	}
	wrong := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": uniqueEmail("nobody"), "code": "000000"}, nil)
	if wrong.Status != 400 {
		t.Fatalf("verifying a code for an unknown email: %d", wrong.Status)
	}
}

func TestForgotPasswordResetsOnceWithAVerifiedCode(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("reset"))
	vault.signUp(t, account)
	anonymous := testsupport.NewBrowser(t, vault.server.Router())
	code := forgotCode(t, anonymous, account.Email)

	if wrong := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": account.Email, "code": "999999"}, nil); wrong.Status != 400 {
		t.Fatalf("a wrong code: %d", wrong.Status)
	}
	verified := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": account.Email, "code": code}, nil)
	if verified.Status != 200 {
		t.Fatalf("verify: %d %s", verified.Status, verified.Raw)
	}
	bundle := verified.Body["bundle"].(map[string]any)
	if bundle["amkRecovery"] == nil || bundle["amkPassword"] == nil {
		t.Fatalf("the recovery wrap must be released after verification: %v", bundle)
	}
	reset := account.PasswordChange(1, testsupport.RandomKey())
	reset["resetToken"] = verified.Body["resetToken"]
	if done := anonymous.Do("POST", "/vault/forgot/reset", reset, nil); done.Status != 200 {
		t.Fatalf("reset: %d %s", done.Status, done.Raw)
	}
	if replay := anonymous.Do("POST", "/vault/forgot/reset", reset, nil); replay.Status != 403 {
		t.Fatalf("a reset token works once, got %d", replay.Status)
	}
	if reused := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": account.Email, "code": code}, nil); reused.Status != 400 {
		t.Fatalf("a code works once, got %d", reused.Status)
	}
}

func TestForgotPasswordLocksAfterTooManyWrongCodes(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("lock"))
	vault.signUp(t, account)
	anonymous := testsupport.NewBrowser(t, vault.server.Router())
	code := forgotCode(t, anonymous, account.Email)
	for attempt := 0; attempt < codeMaxAttempts; attempt++ {
		anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": account.Email, "code": "000000"}, nil)
	}
	locked := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": account.Email, "code": code}, nil)
	if locked.Status != 429 && locked.Status != 400 {
		t.Fatalf("status %d", locked.Status)
	}
	if locked.Status == 200 {
		t.Fatal("the right code must not work after the lock")
	}
}

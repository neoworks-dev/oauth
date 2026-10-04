package vault

import (
	"fmt"
	"testing"

	"github.com/neoworks/oauth/internal/testsupport"
)

func uniqueEmail(label string) string {
	return fmt.Sprintf("%s-%s@example.com", label, testsupport.NewAccount("x@example.com").UserID[:8])
}

func TestPreloginHidesWhichAccountsExist(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("known"))
	vault.signUp(t, account)

	known := vault.browser.Do("POST", "/vault/prelogin", map[string]any{"email": account.Email}, nil)
	unknown := vault.browser.Do("POST", "/vault/prelogin", map[string]any{"email": uniqueEmail("ghost")}, nil)
	unknownAgain := vault.browser.Do("POST", "/vault/prelogin", map[string]any{"email": "ghost-fixed@example.com"}, nil)
	unknownRepeat := vault.browser.Do("POST", "/vault/prelogin", map[string]any{"email": "ghost-fixed@example.com"}, nil)

	if known.Status != 200 || unknown.Status != 200 {
		t.Fatalf("prelogin must answer 200 for everyone: %d %d", known.Status, unknown.Status)
	}
	for _, response := range []testsupport.Response{known, unknown} {
		if len(response.Body) != 3 || response.Body["ops"] != float64(3) || response.Body["mem"] != float64(67108864) {
			t.Fatalf("unexpected shape %v", response.Body)
		}
	}
	if unknownAgain.Body["salt"] != unknownRepeat.Body["salt"] {
		t.Fatal("fake parameters must be deterministic per email")
	}
	if unknown.Body["salt"] == unknownAgain.Body["salt"] {
		t.Fatal("fake parameters must differ per email")
	}
}

func TestPreloginReturnsTheStoredSaltForAKnownAccount(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("salted"))
	request := account.SignupRequest()
	vault.verifyEmail(t, account.Email)
	created := vault.browser.Do("POST", "/vault/signup", request, nil)
	if created.Status != 200 {
		t.Fatalf("signup: %d %s", created.Status, created.Raw)
	}
	prelogin := vault.browser.Do("POST", "/vault/prelogin", map[string]any{"email": account.Email}, nil)
	wantSalt := request["pwhash"].(map[string]any)["salt"]
	if prelogin.Body["salt"] != wantSalt {
		t.Fatalf("salt %v, want %v", prelogin.Body["salt"], wantSalt)
	}
}

func TestLoginVerifiesTheAuthKey(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("login"))
	vault.signUp(t, account)
	other := testsupport.NewBrowserFor(t, vault.server.Router())

	wrong := other.Do("POST", "/vault/login", map[string]any{
		"email": account.Email, "authKey": testsupport.NewAccount("y@example.com").AuthKeyText(), "deviceId": account.DeviceID,
	}, nil)
	ghost := other.Do("POST", "/vault/login", map[string]any{
		"email": uniqueEmail("ghost"), "authKey": account.AuthKeyText(), "deviceId": account.DeviceID,
	}, nil)
	if wrong.Status != 401 || ghost.Status != 401 || string(wrong.Raw) != string(ghost.Raw) {
		t.Fatalf("wrong key and unknown email must be indistinguishable: %d %s / %d %s", wrong.Status, wrong.Raw, ghost.Status, ghost.Raw)
	}

	good := other.Do("POST", "/vault/login", map[string]any{
		"email": account.Email, "authKey": account.AuthKeyText(), "deviceId": account.DeviceID, "deviceName": "Laptop",
	}, nil)
	if good.Status != 200 || good.Body["userId"] != account.UserID {
		t.Fatalf("login: %d %s", good.Status, good.Raw)
	}
	bundle := good.Body["bundle"].(map[string]any)
	if bundle["amkPassword"] == nil || bundle["pwhashSalt"] == nil {
		t.Fatalf("login must return the wrapped AMK and the salt: %v", bundle)
	}
	session := other.Do("GET", "/vault/session", nil, nil)
	if session.Body["authenticated"] != true {
		t.Fatalf("session after login: %s", session.Raw)
	}
}

func TestLoginRejectsMalformedAuthKeys(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("malformed"))
	vault.signUp(t, account)
	other := testsupport.NewBrowserFor(t, vault.server.Router())
	for _, authKey := range []string{"", "short", account.AuthKeyText() + "=", account.AuthKeyText() + "A"} {
		response := other.Do("POST", "/vault/login", map[string]any{"email": account.Email, "authKey": authKey, "deviceId": account.DeviceID}, nil)
		if response.Status != 400 {
			t.Errorf("authKey %q: status %d, want 400", authKey, response.Status)
		}
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	vault := newTestVault(t)
	email := uniqueEmail("limited")
	account := testsupport.NewAccount(email)
	var last testsupport.Response
	for attempt := 0; attempt < loginMaxPerEmail+2; attempt++ {
		last = vault.browser.Do("POST", "/vault/login", map[string]any{"email": email, "authKey": account.AuthKeyText(), "deviceId": account.DeviceID}, nil)
	}
	if last.Status != 429 {
		t.Fatalf("status %d, want 429", last.Status)
	}
}

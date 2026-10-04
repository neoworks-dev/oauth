package vault

import (
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func authenticatorBrowser(t *testing.T, vault *testVault) *testsupport.Browser {
	t.Helper()
	router := chi.NewRouter()
	vault.server.AuthenticatorRouter(router)
	return testsupport.NewBrowser(t, router)
}

func deviceLoginBody(account *testsupport.Account, deviceID string) map[string]any {
	return map[string]any{
		"email": account.Email, "authKey": account.AuthKeyText(), "deviceId": deviceID, "deviceName": "Pixel",
	}
}

func TestDeviceLoginIssuesAuthenticatorTokensAndTheBundle(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("device"))
	vault.signUp(t, account)
	phone := authenticatorBrowser(t, vault)

	deviceID := uuid.NewString()
	login := phone.Do("POST", "/oauth/device-login", deviceLoginBody(account, deviceID), nil)
	if login.Status != 200 {
		t.Fatalf("device login: %d %s", login.Status, login.Raw)
	}
	if login.Body["userId"] != account.UserID || login.Body["bundle"] == nil || login.Body["refresh_token"] == "" {
		t.Fatalf("response: %s", login.Raw)
	}
	accessToken, _ := login.Body["access_token"].(string)
	claims, err := vault.server.issuer.VerifyAccessToken(accessToken)
	if err != nil || claims.ClientID != "neoworks-authenticator" || claims.Subject != account.UserID || claims.InstallID != "" {
		t.Fatalf("token claims: %+v %v", claims, err)
	}

	sessionID := uuid.NewString()
	vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": sessionID}, nil)
	delivered := phone.Do("POST", "/vault/handover/"+sessionID, map[string]any{
		"userId": account.UserID, "deviceId": deviceID, "sealed": sealedAMK(),
	}, authenticatorHeader(accessToken))
	if delivered.Status != 200 {
		t.Fatalf("the device-login token must deliver a handover: %d %s", delivered.Status, delivered.Raw)
	}
}

func TestDeviceLoginRefusesWrongCredentialsAndRevokedDevices(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("device-refused"))
	vault.signUp(t, account)
	phone := authenticatorBrowser(t, vault)

	wrong := deviceLoginBody(account, uuid.NewString())
	wrong["authKey"] = testsupport.NewAccount("other@example.com").AuthKeyText()
	if response := phone.Do("POST", "/oauth/device-login", wrong, nil); response.Status != 401 {
		t.Fatalf("wrong authKey: %d, want 401", response.Status)
	}
	if response := phone.Do("POST", "/oauth/device-login", map[string]any{"email": account.Email}, nil); response.Status != 400 {
		t.Fatalf("missing fields: %d, want 400", response.Status)
	}

	deviceID := uuid.NewString()
	if response := phone.Do("POST", "/oauth/device-login", deviceLoginBody(account, deviceID), nil); response.Status != 200 {
		t.Fatalf("first login: %d", response.Status)
	}
	if err := testSurreal.Exec("UPDATE $device SET revoked_at = time::now()", map[string]any{"device": models.NewRecordID("device", deviceID)}); err != nil {
		t.Fatal(err)
	}
	if response := phone.Do("POST", "/oauth/device-login", deviceLoginBody(account, deviceID), nil); response.Status != 403 {
		t.Fatalf("revoked device: %d, want 403", response.Status)
	}
}

func TestPreloginIsAvailableToTheAuthenticator(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("device-prelogin"))
	vault.signUp(t, account)
	phone := authenticatorBrowser(t, vault)
	response := phone.Do("POST", "/vault/prelogin", map[string]any{"email": account.Email}, nil)
	if response.Status != 200 || response.Body["salt"] == nil {
		t.Fatalf("prelogin: %d %s", response.Status, response.Raw)
	}
}

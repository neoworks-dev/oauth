package vault

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/wire"
)

func sealedAMK() string {
	recipient := testsupport.NewAccount("x@example.com")
	return wire.EncodeBase64URL(testsupport.Seal(recipient.EncPub, make([]byte, 32)))
}

func authenticatorHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func deliverBody(userID string) map[string]any {
	return map[string]any{"userId": userID, "deviceId": uuid.NewString(), "sealed": sealedAMK()}
}

func TestHandoverDeliversTheSealedAMKOnceToTheCreatingSession(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("handover"))
	vault.signUp(t, account)
	sessionID := uuid.NewString()
	created := vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": sessionID}, nil)
	if created.Status != 200 {
		t.Fatalf("create: %d %s", created.Status, created.Raw)
	}
	if pending := vault.browser.Do("GET", "/vault/handover/"+sessionID, nil, nil); pending.Status != 202 {
		t.Fatalf("pending poll: %d", pending.Status)
	}

	token := vault.accessToken(account.UserID, "")
	phone := testsupport.NewBrowser(t, vault.server.Router())
	delivered := phone.Do("POST", "/vault/handover/"+sessionID, deliverBody(account.UserID), authenticatorHeader(token))
	if delivered.Status != 200 {
		t.Fatalf("deliver: %d %s", delivered.Status, delivered.Raw)
	}

	result := vault.browser.Do("GET", "/vault/handover/"+sessionID, nil, nil)
	if result.Status != 200 || result.Body["userId"] != account.UserID || result.Body["sealed"] == "" {
		t.Fatalf("poll: %d %s", result.Status, result.Raw)
	}
	if again := vault.browser.Do("GET", "/vault/handover/"+sessionID, nil, nil); again.Status != 404 {
		t.Fatalf("a delivered handover must be deleted, got %d", again.Status)
	}
}

func TestHandoverCannotBeReadByAnotherBrowserSession(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("binding"))
	vault.signUp(t, account)
	sessionID := uuid.NewString()
	vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": sessionID}, nil)
	phone := testsupport.NewBrowser(t, vault.server.Router())
	phone.Do("POST", "/vault/handover/"+sessionID, deliverBody(account.UserID), authenticatorHeader(vault.accessToken(account.UserID, "")))

	thief := vault.signIn(t, account)
	if stolen := thief.Do("GET", "/vault/handover/"+sessionID, nil, nil); stolen.Status != 404 {
		t.Fatalf("another session of the same user must not read it, got %d %s", stolen.Status, stolen.Raw)
	}
	unauthenticated := testsupport.NewBrowser(t, vault.server.Router())
	if anonymous := unauthenticated.Do("GET", "/vault/handover/"+sessionID, nil, nil); anonymous.Status != 401 {
		t.Fatalf("anonymous read: %d", anonymous.Status)
	}
	if owner := vault.browser.Do("GET", "/vault/handover/"+sessionID, nil, nil); owner.Status != 200 {
		t.Fatalf("the creating session must still read it, got %d", owner.Status)
	}
}

func TestHandoverExpiresAfterOneHundredTwentySeconds(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("ttl"))
	vault.signUp(t, account)
	sessionID := uuid.NewString()
	vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": sessionID}, nil)

	vault.redis.FastForward(119 * time.Second)
	phone := testsupport.NewBrowser(t, vault.server.Router())
	token := authenticatorHeader(vault.accessToken(account.UserID, ""))
	if early := phone.Do("POST", "/vault/handover/"+sessionID, deliverBody(account.UserID), token); early.Status != 200 {
		t.Fatalf("delivery inside the window: %d %s", early.Status, early.Raw)
	}
	vault.redis.FastForward(2 * time.Second)
	if expired := vault.browser.Do("GET", "/vault/handover/"+sessionID, nil, nil); expired.Status != 404 {
		t.Fatalf("a handover must expire after 120 s, got %d", expired.Status)
	}
	other := uuid.NewString()
	vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": other}, nil)
	vault.redis.FastForward(121 * time.Second)
	if late := phone.Do("POST", "/vault/handover/"+other, deliverBody(account.UserID), token); late.Status != 404 {
		t.Fatalf("delivery after expiry: %d", late.Status)
	}
}

func TestHandoverRefusesWrongCallers(t *testing.T) {
	vault := newTestVault(t)
	stranger := testsupport.NewAccount(uniqueEmail("stranger"))
	vault.signUp(t, stranger)
	account := testsupport.NewAccount(uniqueEmail("caller"))
	vault.signUp(t, account)
	sessionID := uuid.NewString()
	vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": sessionID}, nil)
	phone := testsupport.NewBrowser(t, vault.server.Router())
	path := "/vault/handover/" + sessionID

	cases := map[string]struct {
		body   map[string]any
		header map[string]string
		want   int
	}{
		"no token":                {deliverBody(account.UserID), nil, 401},
		"garbage token":           {deliverBody(account.UserID), authenticatorHeader("garbage"), 401},
		"token of another user":   {deliverBody(account.UserID), authenticatorHeader(vault.accessToken(stranger.UserID, "")), 403},
		"claims another user":     {deliverBody(stranger.UserID), authenticatorHeader(vault.accessToken(stranger.UserID, "")), 403},
		"token of another client": {deliverBody(account.UserID), authenticatorHeader(vault.accessTokenFor(account.UserID, "neoworks-calendar", "install-1")), 401},
		"sealed value too short":  {map[string]any{"userId": account.UserID, "deviceId": uuid.NewString(), "sealed": "AAAA"}, authenticatorHeader(vault.accessToken(account.UserID, "")), 400},
		"unregistered session id": {deliverBody(account.UserID), authenticatorHeader(vault.accessToken(account.UserID, "")), 404},
	}
	for name, testCase := range cases {
		target := path
		if name == "unregistered session id" {
			target = "/vault/handover/" + uuid.NewString()
		}
		response := phone.Do("POST", target, testCase.body, testCase.header)
		if response.Status != testCase.want {
			t.Errorf("%s: status %d (%s), want %d", name, response.Status, response.Raw, testCase.want)
		}
	}
}

func TestHandoverCannotBeDeliveredTwice(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("twice"))
	vault.signUp(t, account)
	sessionID := uuid.NewString()
	vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": sessionID}, nil)
	phone := testsupport.NewBrowser(t, vault.server.Router())
	token := authenticatorHeader(vault.accessToken(account.UserID, ""))
	phone.Do("POST", "/vault/handover/"+sessionID, deliverBody(account.UserID), token)
	if second := phone.Do("POST", "/vault/handover/"+sessionID, deliverBody(account.UserID), token); second.Status != 409 {
		t.Fatalf("status %d, want 409", second.Status)
	}
	if duplicate := vault.browser.Do("POST", "/vault/handover", map[string]any{"sessionId": sessionID}, nil); duplicate.Status != 409 {
		t.Fatalf("re-registering a session id: %d", duplicate.Status)
	}
}

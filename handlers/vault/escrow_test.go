package vault

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/wire"
)

// fakeEscrow records calls and answers like the real service would.
type fakeEscrow struct {
	mutex      sync.Mutex
	enrolled   map[string]string
	attempts   map[string]*RecoveryAttempt
	cancelled  map[string]bool
	claimReady bool
	removed    []string
}

func newFakeEscrow() *fakeEscrow {
	return &fakeEscrow{enrolled: map[string]string{}, attempts: map[string]*RecoveryAttempt{}, cancelled: map[string]bool{}}
}

func (escrow *fakeEscrow) Available() bool { return true }

func (escrow *fakeEscrow) Enroll(_ context.Context, userID, sealedAMK string) error {
	escrow.mutex.Lock()
	defer escrow.mutex.Unlock()
	escrow.enrolled[userID] = sealedAMK
	return nil
}

func (escrow *fakeEscrow) Remove(_ context.Context, userID string) error {
	escrow.mutex.Lock()
	defer escrow.mutex.Unlock()
	delete(escrow.enrolled, userID)
	escrow.removed = append(escrow.removed, userID)
	return nil
}

func (escrow *fakeEscrow) StartRecovery(_ context.Context, userID, email, tempPub string) (*RecoveryAttempt, error) {
	escrow.mutex.Lock()
	defer escrow.mutex.Unlock()
	attempt := &RecoveryAttempt{ID: uuid.NewString(), ReadyAt: time.Now().Add(time.Hour), ClaimSecret: "claim-secret", Status: "pending"}
	escrow.attempts[attempt.ID] = attempt
	return attempt, nil
}

func (escrow *fakeEscrow) PendingRecoveries(context.Context, string) ([]RecoveryAttempt, error) {
	escrow.mutex.Lock()
	defer escrow.mutex.Unlock()
	pending := []RecoveryAttempt{}
	for id, attempt := range escrow.attempts {
		if !escrow.cancelled[id] {
			pending = append(pending, *attempt)
		}
	}
	return pending, nil
}

func (escrow *fakeEscrow) CancelAsUser(_ context.Context, _, attemptID string) error {
	escrow.mutex.Lock()
	defer escrow.mutex.Unlock()
	escrow.cancelled[attemptID] = true
	return nil
}

func (escrow *fakeEscrow) CancelWithToken(_ context.Context, attemptID, token string) error {
	if token != "good-token" {
		return ErrRecoveryGone
	}
	return escrow.CancelAsUser(context.Background(), "", attemptID)
}

func (escrow *fakeEscrow) Claim(_ context.Context, _, attemptID, claimSecret string) (string, error) {
	if claimSecret != "claim-secret" {
		return "", ErrRecoverySecret
	}
	if !escrow.claimReady {
		return "", ErrRecoveryNotReady
	}
	return "sealed-amk", nil
}

func sealedBlob() string {
	return wire.EncodeBase64URL(testsupport.Seal(testsupport.NewAccount("x@example.com").EncPub, make([]byte, 32)))
}

func TestSignupWithEscrowEnrollsTheSealedAMK(t *testing.T) {
	escrow := newFakeEscrow()
	vault := newTestVaultWithEscrow(t, escrow)
	account := testsupport.NewAccount(uniqueEmail("escrowsignup"))
	vault.verifyEmail(t, account.Email)
	request := account.SignupRequest()
	request["escrow"] = map[string]any{"sealedAmk": sealedBlob()}
	if response := vault.browser.Do("POST", "/vault/signup", request, nil); response.Status != 200 {
		t.Fatalf("signup: %d %s", response.Status, response.Raw)
	}
	if escrow.enrolled[account.UserID] == "" {
		t.Fatal("the sealed AMK must reach the escrow service")
	}
	status := vault.browser.Do("GET", "/vault/escrow/status", nil, nil)
	if status.Body["enabled"] != true {
		t.Fatalf("status: %s", status.Raw)
	}
}

func TestSignupWithoutEscrowNeverContactsIt(t *testing.T) {
	escrow := newFakeEscrow()
	vault := newTestVaultWithEscrow(t, escrow)
	account := testsupport.NewAccount(uniqueEmail("noescrow"))
	vault.signUp(t, account)
	if len(escrow.enrolled) != 0 {
		t.Fatal("no escrow was chosen")
	}
	if status := vault.browser.Do("GET", "/vault/escrow/status", nil, nil); status.Body["enabled"] != false {
		t.Fatalf("status: %s", status.Raw)
	}
}

func TestEnablingEscrowNeedsThePasswordAndASealedAMK(t *testing.T) {
	escrow := newFakeEscrow()
	vault := newTestVaultWithEscrow(t, escrow)
	account := testsupport.NewAccount(uniqueEmail("enable"))
	vault.signUp(t, account)

	wrong := vault.browser.Do("POST", "/vault/escrow/enable", map[string]any{"currentAuthKey": wire.EncodeBase64URL(testsupport.RandomKey()), "sealedAmk": sealedBlob()}, nil)
	if wrong.Status != 401 {
		t.Fatalf("a wrong password: %d", wrong.Status)
	}
	short := vault.browser.Do("POST", "/vault/escrow/enable", map[string]any{"currentAuthKey": account.AuthKeyText(), "sealedAmk": "AAAA"}, nil)
	if short.Status != 400 {
		t.Fatalf("a malformed seal: %d", short.Status)
	}
	enabled := vault.browser.Do("POST", "/vault/escrow/enable", map[string]any{"currentAuthKey": account.AuthKeyText(), "sealedAmk": sealedBlob()}, nil)
	if enabled.Status != 200 || escrow.enrolled[account.UserID] == "" {
		t.Fatalf("enable: %d %s", enabled.Status, enabled.Raw)
	}
}

func TestRotationReplacesTheEscrowWrapAndDisablingRemovesIt(t *testing.T) {
	escrow := newFakeEscrow()
	vault := newTestVaultWithEscrow(t, escrow)
	account := testsupport.NewAccount(uniqueEmail("rotateescrow"))
	vault.verifyEmail(t, account.Email)
	request := account.SignupRequest()
	request["escrow"] = map[string]any{"sealedAmk": sealedBlob()}
	vault.browser.Do("POST", "/vault/signup", request, nil)
	first := escrow.enrolled[account.UserID]

	missing := vault.browser.Do("POST", "/vault/rotate", account.RotationRequest(1, testsupport.RandomKey()), nil)
	if missing.Status != 400 {
		t.Fatalf("rotating an escrowed account without a new wrap: %d", missing.Status)
	}
	firstKey := testsupport.RandomKey()
	withWrap := account.RotationRequest(1, firstKey)
	withWrap["escrow"] = map[string]any{"sealedAmk": sealedBlob()}
	if rotated := vault.browser.Do("POST", "/vault/rotate", withWrap, nil); rotated.Status != 200 {
		t.Fatalf("rotate: %d %s", rotated.Status, rotated.Raw)
	}
	if escrow.enrolled[account.UserID] == first {
		t.Fatal("the escrow wrap must follow the rotation")
	}

	disable := account.RotationRequest(2, testsupport.RandomKey())
	disable["currentAuthKey"] = wire.EncodeBase64URL(firstKey)
	disable["escrow"] = map[string]any{"disable": true}
	if rotated := vault.browser.Do("POST", "/vault/rotate", disable, nil); rotated.Status != 200 {
		t.Fatalf("rotate and disable: %d %s", rotated.Status, rotated.Raw)
	}
	if len(escrow.removed) != 1 || escrow.removed[0] != account.UserID {
		t.Fatalf("the escrow record must be removed, got %v", escrow.removed)
	}
	if status := vault.browser.Do("GET", "/vault/escrow/status", nil, nil); status.Body["enabled"] != false {
		t.Fatalf("status after disabling: %s", status.Raw)
	}
}

func TestPublicRecoveryNeedsAFreshEmailVerificationAndEscrow(t *testing.T) {
	escrow := newFakeEscrow()
	vault := newTestVaultWithEscrow(t, escrow)
	escrowed := testsupport.NewAccount(uniqueEmail("recoverescrow"))
	vault.verifyEmail(t, escrowed.Email)
	request := escrowed.SignupRequest()
	request["escrow"] = map[string]any{"sealedAmk": sealedBlob()}
	vault.browser.Do("POST", "/vault/signup", request, nil)
	plain := testsupport.NewAccount(uniqueEmail("recoverplain"))
	vault.signUp(t, plain)

	anonymous := testsupport.NewBrowser(t, vault.server.Router())
	tempPub := wire.EncodeBase64URL(testsupport.NewAccount("t@example.com").EncPub[:])
	if refused := anonymous.Do("POST", "/vault/escrow/recovery/start", map[string]any{"resetToken": "forged", "tempPub": tempPub}, nil); refused.Status != 403 {
		t.Fatalf("a forged reset token: %d", refused.Status)
	}

	plainCode := forgotCode(t, anonymous, plain.Email)
	plainVerified := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": plain.Email, "code": plainCode}, nil)
	notEnrolled := anonymous.Do("POST", "/vault/escrow/recovery/start", map[string]any{"resetToken": plainVerified.Body["resetToken"], "tempPub": tempPub}, nil)
	if notEnrolled.Status != 403 {
		t.Fatalf("an account without escrow cannot start one: %d", notEnrolled.Status)
	}

	code := forgotCode(t, anonymous, escrowed.Email)
	verified := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": escrowed.Email, "code": code}, nil)
	if verified.Body["escrowEnabled"] != true {
		t.Fatalf("verify must say that escrow is on: %s", verified.Raw)
	}
	started := anonymous.Do("POST", "/vault/escrow/recovery/start", map[string]any{"resetToken": verified.Body["resetToken"], "tempPub": tempPub}, nil)
	if started.Status != 200 || started.Body["claimSecret"] == "" {
		t.Fatalf("start: %d %s", started.Status, started.Raw)
	}
	claim := map[string]any{"resetToken": verified.Body["resetToken"], "attemptId": started.Body["id"], "claimSecret": "claim-secret"}
	if early := anonymous.Do("POST", "/vault/escrow/recovery/claim", claim, nil); early.Status != 425 {
		t.Fatalf("an early claim: %d %s", early.Status, early.Raw)
	}
	escrow.claimReady = true
	if released := anonymous.Do("POST", "/vault/escrow/recovery/claim", claim, nil); released.Status != 200 || released.Body["sealed"] != "sealed-amk" {
		t.Fatalf("claim: %d %s", released.Status, released.Raw)
	}
	claim["claimSecret"] = "guess"
	if guessed := anonymous.Do("POST", "/vault/escrow/recovery/claim", claim, nil); guessed.Status != 403 {
		t.Fatalf("a wrong claim secret: %d", guessed.Status)
	}
	claim["resetToken"] = "forged"
	if forged := anonymous.Do("POST", "/vault/escrow/recovery/claim", claim, nil); forged.Status != 403 {
		t.Fatalf("a claim without a fresh verification: %d", forged.Status)
	}
}

func TestRecoveryCanBeCancelledByLinkOrByASignedInDevice(t *testing.T) {
	escrow := newFakeEscrow()
	vault := newTestVaultWithEscrow(t, escrow)
	account := testsupport.NewAccount(uniqueEmail("cancel"))
	vault.verifyEmail(t, account.Email)
	request := account.SignupRequest()
	request["escrow"] = map[string]any{"sealedAmk": sealedBlob()}
	vault.browser.Do("POST", "/vault/signup", request, nil)

	anonymous := testsupport.NewBrowser(t, vault.server.Router())
	code := forgotCode(t, anonymous, account.Email)
	verified := anonymous.Do("POST", "/vault/forgot/verify-code", map[string]any{"email": account.Email, "code": code}, nil)
	tempPub := wire.EncodeBase64URL(testsupport.NewAccount("t@example.com").EncPub[:])
	started := anonymous.Do("POST", "/vault/escrow/recovery/start", map[string]any{"resetToken": verified.Body["resetToken"], "tempPub": tempPub}, nil)
	attemptID := started.Body["id"].(string)

	pending := vault.browser.Do("GET", "/vault/escrow/status", nil, nil)
	if recoveries := pending.Body["recoveries"].([]any); len(recoveries) != 1 {
		t.Fatalf("a signed-in device must see the pending recovery: %s", pending.Raw)
	}
	if bad := anonymous.Do("POST", "/vault/escrow/recovery/cancel", map[string]any{"attemptId": attemptID, "token": "wrong"}, nil); bad.Status != 410 {
		t.Fatalf("a wrong cancel token: %d", bad.Status)
	}
	if good := anonymous.Do("POST", "/vault/escrow/recovery/cancel", map[string]any{"attemptId": attemptID, "token": "good-token"}, nil); good.Status != 200 {
		t.Fatalf("the emailed token: %d", good.Status)
	}
	if after := vault.browser.Do("GET", "/vault/escrow/status", nil, nil); len(after.Body["recoveries"].([]any)) != 0 {
		t.Fatalf("a cancelled recovery must disappear: %s", after.Raw)
	}
	if unauthenticated := anonymous.Do("POST", "/vault/escrow/recoveries/"+attemptID+"/cancel", nil, nil); unauthenticated.Status != 401 {
		t.Fatalf("device cancel needs a session: %d", unauthenticated.Status)
	}
}

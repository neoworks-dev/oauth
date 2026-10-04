package escrow

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/neoworks/oauth/internal/mail"
	"golang.org/x/crypto/nacl/box"
)

type recordingMailer struct {
	mutex    sync.Mutex
	messages []mail.Message
}

func (mailer *recordingMailer) Send(_ context.Context, message mail.Message) error {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	mailer.messages = append(mailer.messages, message)
	return nil
}

type fixture struct {
	service    *Service
	repository *MemoryRepository
	mailer     *recordingMailer
	now        time.Time
	amk        []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	repository := NewMemoryRepository()
	mailer := &recordingMailer{}
	result := &fixture{repository: repository, mailer: mailer, now: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}
	result.service = NewService(repository, NewMemoryKMS(), mailer, DevServiceKey(),
		Config{WaitingPeriod: 7 * 24 * time.Hour, CancelBaseURL: "https://vault.test/recover/cancel"},
		func() time.Time { return result.now })
	result.amk = make([]byte, 32)
	_, _ = rand.Read(result.amk)
	return result
}

func (fix *fixture) enroll(t *testing.T, userID string) {
	t.Helper()
	sealed, err := box.SealAnonymous(nil, fix.amk, &fix.service.key.Public, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := fix.service.Enroll(context.Background(), userID, sealed); err != nil {
		t.Fatalf("enroll: %v", err)
	}
}

func newTempKeys(t *testing.T) (*[32]byte, *[32]byte) {
	t.Helper()
	publicKey, secretKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, secretKey
}

func TestEnrollStoresOnlyAKMSEncryptedBlob(t *testing.T) {
	fix := newFixture(t)
	fix.enroll(t, "user-1")
	record, err := fix.repository.GetRecord(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(record.KMSBlob) == 0 || string(record.KMSBlob) == string(fix.amk) {
		t.Fatal("the AMK must be stored encrypted")
	}
	for _, offset := range []int{0, 24} {
		if len(record.KMSBlob) >= offset+32 && string(record.KMSBlob[offset:offset+32]) == string(fix.amk) {
			t.Fatal("the plaintext AMK appears in the stored blob")
		}
	}
}

func TestEnrollRejectsGarbage(t *testing.T) {
	fix := newFixture(t)
	if err := fix.service.Enroll(context.Background(), "user-1", []byte("not a sealed box")); err != ErrInvalidArgument {
		t.Fatalf("got %v", err)
	}
	other, _ := newTempKeys(t)
	sealedToSomeoneElse, _ := box.SealAnonymous(nil, fix.amk, other, rand.Reader)
	if err := fix.service.Enroll(context.Background(), "user-1", sealedToSomeoneElse); err != ErrInvalidArgument {
		t.Fatalf("a box sealed to another key must be refused, got %v", err)
	}
}

func TestRecoveryWaitsThenReleasesTheAMKToTheTemporaryKey(t *testing.T) {
	fix := newFixture(t)
	ctx := context.Background()
	fix.enroll(t, "user-1")
	tempPublic, tempSecret := newTempKeys(t)

	started, err := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:])
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !started.ReadyAt.Equal(fix.now.Add(7 * 24 * time.Hour)) {
		t.Fatalf("ready at %v", started.ReadyAt)
	}
	if len(fix.mailer.messages) != 1 || fix.mailer.messages[0].To[0] != "ada@example.com" {
		t.Fatalf("the account holder must be notified, got %+v", fix.mailer.messages)
	}

	if _, err := fix.service.Claim(ctx, "user-1", started.ID, started.ClaimSecret); err != ErrNotReady {
		t.Fatalf("claiming early must fail, got %v", err)
	}
	fix.now = started.ReadyAt.Add(time.Minute)
	sealed, err := fix.service.Claim(ctx, "user-1", started.ID, started.ClaimSecret)
	if err != nil {
		t.Fatalf("claim after the wait: %v", err)
	}
	amk, ok := box.OpenAnonymous(nil, sealed, tempPublic, tempSecret)
	if !ok || string(amk) != string(fix.amk) {
		t.Fatal("the released AMK must open with the temporary secret")
	}
}

func TestCancellingStopsTheRecoveryFromEitherSide(t *testing.T) {
	cases := map[string]func(fix *fixture, started *StartedRecovery) error{
		"signed-in device": func(fix *fixture, started *StartedRecovery) error {
			return fix.service.CancelAsUser(context.Background(), "user-1", started.ID)
		},
		"email link": func(fix *fixture, started *StartedRecovery) error {
			token := tokenFromMail(fix.mailer.messages[0].Text)
			return fix.service.CancelWithToken(context.Background(), started.ID, token)
		},
	}
	for name, cancel := range cases {
		t.Run(name, func(t *testing.T) {
			fix := newFixture(t)
			ctx := context.Background()
			fix.enroll(t, "user-1")
			tempPublic, _ := newTempKeys(t)
			started, _ := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:])
			if err := cancel(fix, started); err != nil {
				t.Fatalf("cancel: %v", err)
			}
			fix.now = started.ReadyAt.Add(time.Hour)
			if _, err := fix.service.Claim(ctx, "user-1", started.ID, started.ClaimSecret); err != ErrUnavailable {
				t.Fatalf("a cancelled recovery must not release the AMK, got %v", err)
			}
		})
	}
}

func TestCancelRefusesWrongUsersAndTokens(t *testing.T) {
	fix := newFixture(t)
	ctx := context.Background()
	fix.enroll(t, "user-1")
	tempPublic, _ := newTempKeys(t)
	started, _ := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:])
	if err := fix.service.CancelAsUser(ctx, "user-2", started.ID); err != ErrUnavailable {
		t.Fatalf("another user must not cancel, got %v", err)
	}
	if err := fix.service.CancelWithToken(ctx, started.ID, "wrong"); err != ErrUnavailable {
		t.Fatalf("a wrong token must not cancel, got %v", err)
	}
}

func TestClaimNeedsTheClaimSecretAndTheRightUser(t *testing.T) {
	fix := newFixture(t)
	ctx := context.Background()
	fix.enroll(t, "user-1")
	tempPublic, _ := newTempKeys(t)
	started, _ := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:])
	fix.now = started.ReadyAt.Add(time.Minute)

	if _, err := fix.service.Claim(ctx, "user-1", started.ID, "wrong"); err != ErrInvalidSecret {
		t.Fatalf("got %v", err)
	}
	if _, err := fix.service.Claim(ctx, "user-2", started.ID, started.ClaimSecret); err != ErrUnavailable {
		t.Fatalf("got %v", err)
	}
	for attempt := 0; attempt < maxFailedClaims; attempt++ {
		_, _ = fix.service.Claim(ctx, "user-1", started.ID, "wrong")
	}
	if _, err := fix.service.Claim(ctx, "user-1", started.ID, started.ClaimSecret); err != ErrUnavailable {
		t.Fatalf("guessing must lock the attempt, got %v", err)
	}
}

func TestStartIsRateLimitedAndNeedsEnrollment(t *testing.T) {
	fix := newFixture(t)
	ctx := context.Background()
	tempPublic, _ := newTempKeys(t)
	if _, err := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:]); err != ErrNotEnrolled {
		t.Fatalf("got %v", err)
	}
	fix.enroll(t, "user-1")
	first, err := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:]); err != ErrAttemptPending {
		t.Fatalf("a second attempt while one waits must be refused, got %v", err)
	}
	_ = fix.service.CancelAsUser(ctx, "user-1", first.ID)
	for count := 0; count < maxAttemptsPerDay-1; count++ {
		started, err := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:])
		if err != nil {
			t.Fatalf("attempt %d: %v", count, err)
		}
		_ = fix.service.CancelAsUser(ctx, "user-1", started.ID)
	}
	if _, err := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:]); err != ErrRateLimited {
		t.Fatalf("the daily limit must apply, got %v", err)
	}
}

func TestEveryRecoveryStepIsAuditedWithoutKeyMaterial(t *testing.T) {
	fix := newFixture(t)
	ctx := context.Background()
	fix.enroll(t, "user-1")
	tempPublic, _ := newTempKeys(t)
	started, _ := fix.service.StartRecovery(ctx, "user-1", "ada@example.com", tempPublic[:])
	fix.now = started.ReadyAt.Add(time.Minute)
	_, _ = fix.service.Claim(ctx, "user-1", started.ID, started.ClaimSecret)

	events := []string{}
	for _, entry := range fix.repository.Audits {
		events = append(events, entry.Event)
		if entry.Detail != "" && len(entry.Detail) > 64 {
			t.Fatalf("audit detail looks like key material: %q", entry.Detail)
		}
	}
	want := []string{"enroll", "start", "claim"}
	if len(events) != len(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("events %v, want %v", events, want)
		}
	}
}

func TestServiceKeyIsCreatedOnceAndProtectedByTheKMS(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	kms := NewMemoryKMS()
	first, err := LoadOrCreateServiceKey(ctx, repository, kms, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateServiceKey(ctx, repository, kms, false)
	if err != nil || first.Public != second.Public || first.Secret != second.Secret {
		t.Fatalf("the key must be stable: %v", err)
	}
	_, storedSecret, _ := repository.GetServiceKey(ctx)
	if string(storedSecret) == string(first.Secret[:]) {
		t.Fatal("the service secret must be stored encrypted")
	}
	if _, err := LoadOrCreateServiceKey(ctx, repository, NewMemoryKMS(), false); err == nil {
		t.Fatal("another KMS key must not open the service key")
	}
}

func tokenFromMail(text string) string {
	marker := "&t="
	start := -1
	for index := 0; index+len(marker) <= len(text); index++ {
		if text[index:index+len(marker)] == marker {
			start = index + len(marker)
			break
		}
	}
	end := start
	for end < len(text) && text[end] != '\n' && text[end] != ' ' {
		end++
	}
	return text[start:end]
}

package escrow

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/neoworks/oauth/internal/testsupport"
	"golang.org/x/crypto/nacl/box"
)

var testSurreal *testsupport.Surreal

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	surreal, err := testsupport.StartSurreal()
	if err != nil {
		panic(err)
	}
	testSurreal = surreal
	code := m.Run()
	if surreal != nil {
		surreal.Stop()
	}
	os.Exit(code)
}

func surrealRepository(t *testing.T) *SurrealRepository {
	t.Helper()
	if testSurreal == nil {
		t.Skip("surreal binary not available")
	}
	repository := NewSurrealRepository(testSurreal.DB())
	if err := repository.DefineSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestSurrealRepositoryRunsTheWholeRecovery(t *testing.T) {
	repository := surrealRepository(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	mailer := &recordingMailer{}
	service := NewService(repository, NewMemoryKMS(), mailer, DevServiceKey(),
		Config{WaitingPeriod: time.Hour, CancelBaseURL: "https://vault.test/recover/cancel"}, clock)

	amk := make([]byte, 32)
	_, _ = rand.Read(amk)
	sealed, _ := box.SealAnonymous(nil, amk, &service.key.Public, rand.Reader)
	if err := service.Enroll(ctx, "surreal-user", sealed); err != nil {
		t.Fatal(err)
	}
	tempPublic, tempSecret, _ := box.GenerateKey(rand.Reader)
	started, err := service.StartRecovery(ctx, "surreal-user", "ada@example.com", tempPublic[:])
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.Pending(ctx, "surreal-user")
	if err != nil || len(pending) != 1 || pending[0].ID != started.ID {
		t.Fatalf("pending %+v err %v", pending, err)
	}
	now = now.Add(2 * time.Hour)
	released, err := service.Claim(ctx, "surreal-user", started.ID, started.ClaimSecret)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	opened, ok := box.OpenAnonymous(nil, released, tempPublic, tempSecret)
	if !ok || string(opened) != string(amk) {
		t.Fatal("wrong AMK released")
	}
	if err := service.Remove(ctx, "surreal-user"); err != nil {
		t.Fatal(err)
	}
	if enrolled, _ := service.IsEnrolled(ctx, "surreal-user"); enrolled {
		t.Fatal("removed record must be gone")
	}
}

func TestSurrealServiceKeyPersists(t *testing.T) {
	repository := surrealRepository(t)
	ctx := context.Background()
	kms := NewMemoryKMS()
	first, err := LoadOrCreateServiceKey(ctx, repository, kms, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateServiceKey(ctx, repository, kms, false)
	if err != nil || first.Public != second.Public {
		t.Fatalf("service key must persist: %v", err)
	}
}

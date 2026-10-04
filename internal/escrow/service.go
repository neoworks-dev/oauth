package escrow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neoworks/oauth/internal/mail"
	"golang.org/x/crypto/nacl/box"
)

const (
	amkBytes            = 32
	recoveryClaimWindow = 48 * time.Hour
	maxAttemptsPerDay   = 3
	maxFailedClaims     = 10
)

var (
	ErrNotEnrolled     = errors.New("user has no escrow record")
	ErrRateLimited     = errors.New("too many recovery attempts")
	ErrAttemptPending  = errors.New("a recovery is already waiting")
	ErrNotReady        = errors.New("waiting period has not ended")
	ErrUnavailable     = errors.New("recovery attempt is cancelled, expired or unknown")
	ErrInvalidSecret   = errors.New("invalid secret")
	ErrInvalidArgument = errors.New("invalid argument")
)

// Clock lets tests move time.
type Clock func() time.Time

// Config holds the service parameters.
type Config struct {
	WaitingPeriod time.Duration
	CancelBaseURL string
}

type Service struct {
	repository Repository
	kms        KMS
	mailer     mail.Sender
	key        ServiceKey
	config     Config
	now        Clock
}

func NewService(repository Repository, kms KMS, mailer mail.Sender, key ServiceKey, config Config, clock Clock) *Service {
	return &Service{repository: repository, kms: kms, mailer: mailer, key: key, config: config, now: clock}
}

func (service *Service) PublicKey() []byte {
	publicKey := service.key.Public
	return publicKey[:]
}

// Enroll stores the AMK a client sealed to the service key. The plaintext AMK
// exists only inside this call.
func (service *Service) Enroll(ctx context.Context, userID string, sealedAMK []byte) error {
	if userID == "" {
		return ErrInvalidArgument
	}
	amk, ok := box.OpenAnonymous(nil, sealedAMK, &service.key.Public, &service.key.Secret)
	if !ok || len(amk) != amkBytes {
		return ErrInvalidArgument
	}
	defer wipe(amk)
	blob, err := service.kms.Encrypt(ctx, amk, []byte(userID))
	if err != nil {
		return err
	}
	now := service.now()
	if err := service.repository.PutRecord(ctx, Record{UserID: userID, KMSBlob: blob, EnrolledAt: now, UpdatedAt: now}); err != nil {
		return err
	}
	return service.audit(ctx, "enroll", userID, "", "")
}

func (service *Service) Remove(ctx context.Context, userID string) error {
	if err := service.repository.DeleteRecord(ctx, userID); err != nil {
		return err
	}
	return service.audit(ctx, "remove", userID, "", "")
}

func (service *Service) IsEnrolled(ctx context.Context, userID string) (bool, error) {
	_, err := service.repository.GetRecord(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// StartedRecovery is what the caller gets back from starting a recovery. The
// claim secret and cancel token are shown only here.
type StartedRecovery struct {
	ID          string
	ReadyAt     time.Time
	ClaimSecret string
}

// StartRecovery begins the waiting period. The caller has already verified the
// email address. Every start is rate limited and audited, and the address is
// told how to cancel.
func (service *Service) StartRecovery(ctx context.Context, userID, email string, tempPub []byte) (*StartedRecovery, error) {
	if userID == "" || email == "" || len(tempPub) != boxKeySize {
		return nil, ErrInvalidArgument
	}
	if enrolled, err := service.IsEnrolled(ctx, userID); err != nil || !enrolled {
		_ = service.audit(ctx, "start_refused_not_enrolled", userID, "", "")
		return nil, ErrNotEnrolled
	}
	if err := service.checkStartLimits(ctx, userID); err != nil {
		_ = service.audit(ctx, "start_refused_limit", userID, "", err.Error())
		return nil, err
	}
	return service.createAttempt(ctx, userID, email, tempPub)
}

func (service *Service) checkStartLimits(ctx context.Context, userID string) error {
	now := service.now()
	recent, err := service.repository.ListAttempts(ctx, userID, now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	if len(recent) >= maxAttemptsPerDay {
		return ErrRateLimited
	}
	for _, attempt := range recent {
		if attempt.Status == StatusPending && now.Before(attempt.ExpiresAt) {
			return ErrAttemptPending
		}
	}
	return nil
}

func (service *Service) createAttempt(ctx context.Context, userID, email string, tempPub []byte) (*StartedRecovery, error) {
	now := service.now()
	claimSecret := randomToken()
	cancelToken := randomToken()
	attempt := Attempt{
		ID: uuid.NewString(), UserID: userID, Email: email, TempPub: tempPub,
		ClaimSecretHash: hashToken(claimSecret), CancelTokenHash: hashToken(cancelToken),
		Status: StatusPending, CreatedAt: now, ReadyAt: now.Add(service.config.WaitingPeriod),
	}
	attempt.ExpiresAt = attempt.ReadyAt.Add(recoveryClaimWindow)
	if err := service.repository.CreateAttempt(ctx, attempt); err != nil {
		return nil, err
	}
	if err := service.audit(ctx, "start", userID, attempt.ID, ""); err != nil {
		return nil, err
	}
	service.notifyStarted(ctx, attempt, cancelToken)
	return &StartedRecovery{ID: attempt.ID, ReadyAt: attempt.ReadyAt, ClaimSecret: claimSecret}, nil
}

// notifyStarted emails the account holder. A failed email does not stop the
// recovery; the wait protects the account either way.
func (service *Service) notifyStarted(ctx context.Context, attempt Attempt, cancelToken string) {
	cancelLink := fmt.Sprintf("%s#a=%s&t=%s", service.config.CancelBaseURL, attempt.ID, cancelToken)
	text := fmt.Sprintf(
		"Someone asked to recover access to your Neoworks account with the help of Neoworks.\n\n"+
			"Access can be restored on %s. If this was not you, cancel it now:\n%s\n\n"+
			"You can also cancel it from any device where you are signed in.",
		attempt.ReadyAt.UTC().Format(time.RFC1123), cancelLink)
	_ = service.mailer.Send(ctx, mail.Message{To: []string{attempt.Email}, Subject: "Account recovery requested", Text: text})
}

// Pending lists a user's recoveries that are still waiting or claimable.
func (service *Service) Pending(ctx context.Context, userID string) ([]Attempt, error) {
	now := service.now()
	attempts, err := service.repository.ListAttempts(ctx, userID, now.Add(-recoveryClaimWindow-service.config.WaitingPeriod))
	if err != nil {
		return nil, err
	}
	pending := []Attempt{}
	for _, attempt := range attempts {
		if attempt.Status == StatusPending && now.Before(attempt.ExpiresAt) {
			pending = append(pending, attempt)
		}
	}
	return pending, nil
}

// CancelAsUser cancels an attempt on behalf of a signed-in device of the user.
func (service *Service) CancelAsUser(ctx context.Context, userID, attemptID string) error {
	attempt, err := service.repository.GetAttempt(ctx, attemptID)
	if err != nil || attempt.UserID != userID {
		return ErrUnavailable
	}
	return service.cancel(ctx, attempt, "cancel_device")
}

// CancelWithToken cancels an attempt with the token from the notification email.
func (service *Service) CancelWithToken(ctx context.Context, attemptID, token string) error {
	attempt, err := service.repository.GetAttempt(ctx, attemptID)
	if err != nil || !tokenMatches(attempt.CancelTokenHash, token) {
		return ErrUnavailable
	}
	return service.cancel(ctx, attempt, "cancel_email")
}

func (service *Service) cancel(ctx context.Context, attempt *Attempt, event string) error {
	if attempt.Status == StatusCancelled {
		return nil
	}
	cancelledAt := service.now()
	attempt.Status = StatusCancelled
	attempt.CancelledAt = &cancelledAt
	if err := service.repository.UpdateAttempt(ctx, *attempt); err != nil {
		return err
	}
	_ = service.mailer.Send(ctx, mail.Message{
		To: []string{attempt.Email}, Subject: "Account recovery cancelled",
		Text: "The recovery of your Neoworks account was cancelled.",
	})
	return service.audit(ctx, event, attempt.UserID, attempt.ID, "")
}

// Claim releases the AMK, sealed to the attempt's temporary key, once the
// waiting period has ended. The plaintext AMK exists only inside this call.
func (service *Service) Claim(ctx context.Context, userID, attemptID, claimSecret string) ([]byte, error) {
	attempt, err := service.repository.GetAttempt(ctx, attemptID)
	if err != nil || attempt.UserID != userID {
		return nil, ErrUnavailable
	}
	now := service.now()
	if attempt.Status != StatusPending || !now.Before(attempt.ExpiresAt) || attempt.FailedClaimCount >= maxFailedClaims {
		return nil, ErrUnavailable
	}
	if !tokenMatches(attempt.ClaimSecretHash, claimSecret) {
		return nil, service.recordFailedClaim(ctx, attempt)
	}
	if now.Before(attempt.ReadyAt) {
		return nil, ErrNotReady
	}
	return service.releaseAMK(ctx, attempt)
}

func (service *Service) recordFailedClaim(ctx context.Context, attempt *Attempt) error {
	attempt.FailedClaimCount++
	if err := service.repository.UpdateAttempt(ctx, *attempt); err != nil {
		return err
	}
	_ = service.audit(ctx, "claim_failed", attempt.UserID, attempt.ID, "")
	return ErrInvalidSecret
}

func (service *Service) releaseAMK(ctx context.Context, attempt *Attempt) ([]byte, error) {
	record, err := service.repository.GetRecord(ctx, attempt.UserID)
	if err != nil {
		return nil, ErrNotEnrolled
	}
	amk, err := service.kms.Decrypt(ctx, record.KMSBlob, []byte(attempt.UserID))
	if err != nil {
		return nil, err
	}
	defer wipe(amk)
	var tempPub [boxKeySize]byte
	copy(tempPub[:], attempt.TempPub)
	sealed, err := box.SealAnonymous(nil, amk, &tempPub, rand.Reader)
	if err != nil {
		return nil, err
	}
	claimedAt := service.now()
	attempt.ClaimedAt = &claimedAt
	if err := service.repository.UpdateAttempt(ctx, *attempt); err != nil {
		return nil, err
	}
	return sealed, service.audit(ctx, "claim", attempt.UserID, attempt.ID, "")
}

func (service *Service) audit(ctx context.Context, event, userID, attemptID, detail string) error {
	return service.repository.Audit(ctx, AuditEntry{At: service.now(), Event: event, UserID: userID, AttemptID: attemptID, Detail: detail})
}

func randomToken() string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func hashToken(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}

func tokenMatches(expectedHash []byte, token string) bool {
	return subtle.ConstantTimeCompare(expectedHash, hashToken(token)) == 1
}

func wipe(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}

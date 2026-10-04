package escrow

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Record is one user's escrowed AMK, encrypted by the KMS.
type Record struct {
	UserID     string
	KMSBlob    []byte
	EnrolledAt time.Time
	UpdatedAt  time.Time
}

// Attempt statuses.
const (
	StatusPending   = "pending"
	StatusCancelled = "cancelled"
)

// Attempt is one recovery request. Secrets are stored only as hashes.
type Attempt struct {
	ID               string
	UserID           string
	Email            string
	TempPub          []byte
	ClaimSecretHash  []byte
	CancelTokenHash  []byte
	Status           string
	CreatedAt        time.Time
	ReadyAt          time.Time
	ExpiresAt        time.Time
	CancelledAt      *time.Time
	ClaimedAt        *time.Time
	FailedClaimCount int
}

// AuditEntry is an append-only log line. It never holds key material.
type AuditEntry struct {
	At        time.Time
	Event     string
	UserID    string
	AttemptID string
	Detail    string
}

// Repository is the escrow service's own storage.
type Repository interface {
	GetRecord(ctx context.Context, userID string) (*Record, error)
	PutRecord(ctx context.Context, record Record) error
	DeleteRecord(ctx context.Context, userID string) error
	CreateAttempt(ctx context.Context, attempt Attempt) error
	GetAttempt(ctx context.Context, attemptID string) (*Attempt, error)
	UpdateAttempt(ctx context.Context, attempt Attempt) error
	ListAttempts(ctx context.Context, userID string, since time.Time) ([]Attempt, error)
	Audit(ctx context.Context, entry AuditEntry) error
	GetServiceKey(ctx context.Context) ([]byte, []byte, error)
	PutServiceKey(ctx context.Context, publicKey, sealedSecret []byte) error
}

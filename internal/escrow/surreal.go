package escrow

import (
	"context"
	"encoding/base64"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// SurrealRepository stores escrow state in the service's own SurrealDB
// namespace. Binary values are base64url strings.
type SurrealRepository struct {
	db *surrealdb.DB
}

// OpenSurreal connects to the escrow namespace.
func OpenSurreal(ctx context.Context, url, user, password, namespace, database string) (*SurrealRepository, error) {
	db, err := surrealdb.FromEndpointURLString(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := db.SignIn(ctx, surrealdb.Auth{Username: user, Password: password}); err != nil {
		return nil, err
	}
	if err := db.Use(ctx, namespace, database); err != nil {
		return nil, err
	}
	return &SurrealRepository{db: db}, nil
}

func NewSurrealRepository(db *surrealdb.DB) *SurrealRepository {
	return &SurrealRepository{db: db}
}

// DefineSchema creates the tables. It is idempotent.
func (repository *SurrealRepository) DefineSchema(ctx context.Context) error {
	statements := `
		DEFINE TABLE IF NOT EXISTS escrow_record SCHEMALESS;
		DEFINE TABLE IF NOT EXISTS recovery_attempt SCHEMALESS;
		DEFINE INDEX IF NOT EXISTS recovery_attempt_user ON recovery_attempt FIELDS user_id;
		DEFINE TABLE IF NOT EXISTS audit_log SCHEMALESS;
		DEFINE TABLE IF NOT EXISTS service_key SCHEMALESS;`
	_, err := surrealdb.Query[any](ctx, repository.db, statements, nil)
	return err
}

func encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decode(text string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(text)
	return decoded
}

func query[Row any](ctx context.Context, repository *SurrealRepository, sql string, vars map[string]any) ([]Row, error) {
	results, err := surrealdb.Query[[]Row](ctx, repository.db, sql, vars)
	if err != nil {
		return nil, err
	}
	if len(*results) == 0 {
		return nil, nil
	}
	return (*results)[len(*results)-1].Result, nil
}

type recordRow struct {
	UserID     string    `json:"user_id"`
	KMSBlob    string    `json:"kms_blob"`
	EnrolledAt time.Time `json:"enrolled_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (repository *SurrealRepository) GetRecord(ctx context.Context, userID string) (*Record, error) {
	rows, err := query[recordRow](ctx, repository, "SELECT * FROM $id", map[string]any{"id": models.NewRecordID("escrow_record", userID)})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return &Record{UserID: rows[0].UserID, KMSBlob: decode(rows[0].KMSBlob), EnrolledAt: rows[0].EnrolledAt, UpdatedAt: rows[0].UpdatedAt}, nil
}

func (repository *SurrealRepository) PutRecord(ctx context.Context, record Record) error {
	_, err := query[any](ctx, repository, "UPSERT $id CONTENT $content", map[string]any{
		"id": models.NewRecordID("escrow_record", record.UserID),
		"content": map[string]any{
			"user_id": record.UserID, "kms_blob": encode(record.KMSBlob),
			"enrolled_at": record.EnrolledAt, "updated_at": record.UpdatedAt,
		},
	})
	return err
}

func (repository *SurrealRepository) DeleteRecord(ctx context.Context, userID string) error {
	_, err := query[any](ctx, repository, "DELETE $id", map[string]any{"id": models.NewRecordID("escrow_record", userID)})
	return err
}

type attemptRow struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	Email            string     `json:"email"`
	TempPub          string     `json:"temp_pub"`
	ClaimSecretHash  string     `json:"claim_secret_hash"`
	CancelTokenHash  string     `json:"cancel_token_hash"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	ReadyAt          time.Time  `json:"ready_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	CancelledAt      *time.Time `json:"cancelled_at"`
	ClaimedAt        *time.Time `json:"claimed_at"`
	FailedClaimCount int        `json:"failed_claim_count"`
}

const attemptColumns = `record::id(id) AS id, user_id, email, temp_pub, claim_secret_hash, cancel_token_hash,
	status, created_at, ready_at, expires_at, cancelled_at, claimed_at, failed_claim_count`

func (row attemptRow) toAttempt() Attempt {
	return Attempt{
		ID: row.ID, UserID: row.UserID, Email: row.Email, TempPub: decode(row.TempPub),
		ClaimSecretHash: decode(row.ClaimSecretHash), CancelTokenHash: decode(row.CancelTokenHash),
		Status: row.Status, CreatedAt: row.CreatedAt, ReadyAt: row.ReadyAt, ExpiresAt: row.ExpiresAt,
		CancelledAt: row.CancelledAt, ClaimedAt: row.ClaimedAt, FailedClaimCount: row.FailedClaimCount,
	}
}

func attemptContent(attempt Attempt) map[string]any {
	content := map[string]any{
		"user_id": attempt.UserID, "email": attempt.Email, "temp_pub": encode(attempt.TempPub),
		"claim_secret_hash": encode(attempt.ClaimSecretHash), "cancel_token_hash": encode(attempt.CancelTokenHash),
		"status": attempt.Status, "created_at": attempt.CreatedAt, "ready_at": attempt.ReadyAt,
		"expires_at": attempt.ExpiresAt, "failed_claim_count": attempt.FailedClaimCount,
	}
	if attempt.CancelledAt != nil {
		content["cancelled_at"] = *attempt.CancelledAt
	}
	if attempt.ClaimedAt != nil {
		content["claimed_at"] = *attempt.ClaimedAt
	}
	return content
}

func (repository *SurrealRepository) CreateAttempt(ctx context.Context, attempt Attempt) error {
	_, err := query[any](ctx, repository, "CREATE $id CONTENT $content", map[string]any{
		"id": models.NewRecordID("recovery_attempt", attempt.ID), "content": attemptContent(attempt),
	})
	return err
}

func (repository *SurrealRepository) UpdateAttempt(ctx context.Context, attempt Attempt) error {
	_, err := query[any](ctx, repository, "UPDATE $id CONTENT $content", map[string]any{
		"id": models.NewRecordID("recovery_attempt", attempt.ID), "content": attemptContent(attempt),
	})
	return err
}

func (repository *SurrealRepository) GetAttempt(ctx context.Context, attemptID string) (*Attempt, error) {
	rows, err := query[attemptRow](ctx, repository, "SELECT "+attemptColumns+" FROM $id",
		map[string]any{"id": models.NewRecordID("recovery_attempt", attemptID)})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	attempt := rows[0].toAttempt()
	return &attempt, nil
}

func (repository *SurrealRepository) ListAttempts(ctx context.Context, userID string, since time.Time) ([]Attempt, error) {
	rows, err := query[attemptRow](ctx, repository,
		"SELECT "+attemptColumns+" FROM recovery_attempt WHERE user_id = $user_id AND created_at >= $since",
		map[string]any{"user_id": userID, "since": since})
	if err != nil {
		return nil, err
	}
	attempts := make([]Attempt, 0, len(rows))
	for _, row := range rows {
		attempts = append(attempts, row.toAttempt())
	}
	return attempts, nil
}

func (repository *SurrealRepository) Audit(ctx context.Context, entry AuditEntry) error {
	_, err := query[any](ctx, repository, "CREATE audit_log CONTENT $content", map[string]any{
		"content": map[string]any{
			"at": entry.At, "event": entry.Event, "user_id": entry.UserID,
			"attempt_id": entry.AttemptID, "detail": entry.Detail,
		},
	})
	return err
}

type serviceKeyRow struct {
	PublicKey    string `json:"public_key"`
	SealedSecret string `json:"sealed_secret"`
}

func (repository *SurrealRepository) GetServiceKey(ctx context.Context) ([]byte, []byte, error) {
	rows, err := query[serviceKeyRow](ctx, repository, "SELECT * FROM service_key:current", nil)
	if err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, ErrNotFound
	}
	return decode(rows[0].PublicKey), decode(rows[0].SealedSecret), nil
}

func (repository *SurrealRepository) PutServiceKey(ctx context.Context, publicKey, sealedSecret []byte) error {
	_, err := query[any](ctx, repository, "UPSERT service_key:current CONTENT $content", map[string]any{
		"content": map[string]any{"public_key": encode(publicKey), "sealed_secret": encode(sealedSecret)},
	})
	return err
}

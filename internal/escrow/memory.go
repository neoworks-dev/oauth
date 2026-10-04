package escrow

import (
	"context"
	"sync"
	"time"
)

// MemoryRepository keeps everything in memory, for tests.
type MemoryRepository struct {
	mutex     sync.Mutex
	records   map[string]Record
	attempts  map[string]Attempt
	Audits    []AuditEntry
	publicKey []byte
	secret    []byte
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{records: map[string]Record{}, attempts: map[string]Attempt{}}
}

func (repository *MemoryRepository) GetRecord(_ context.Context, userID string) (*Record, error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	record, found := repository.records[userID]
	if !found {
		return nil, ErrNotFound
	}
	return &record, nil
}

func (repository *MemoryRepository) PutRecord(_ context.Context, record Record) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	repository.records[record.UserID] = record
	return nil
}

func (repository *MemoryRepository) DeleteRecord(_ context.Context, userID string) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	delete(repository.records, userID)
	return nil
}

func (repository *MemoryRepository) CreateAttempt(_ context.Context, attempt Attempt) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	repository.attempts[attempt.ID] = attempt
	return nil
}

func (repository *MemoryRepository) GetAttempt(_ context.Context, attemptID string) (*Attempt, error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	attempt, found := repository.attempts[attemptID]
	if !found {
		return nil, ErrNotFound
	}
	return &attempt, nil
}

func (repository *MemoryRepository) UpdateAttempt(_ context.Context, attempt Attempt) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	repository.attempts[attempt.ID] = attempt
	return nil
}

func (repository *MemoryRepository) ListAttempts(_ context.Context, userID string, since time.Time) ([]Attempt, error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	listed := []Attempt{}
	for _, attempt := range repository.attempts {
		if attempt.UserID == userID && !attempt.CreatedAt.Before(since) {
			listed = append(listed, attempt)
		}
	}
	return listed, nil
}

func (repository *MemoryRepository) Audit(_ context.Context, entry AuditEntry) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	repository.Audits = append(repository.Audits, entry)
	return nil
}

func (repository *MemoryRepository) GetServiceKey(_ context.Context) ([]byte, []byte, error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	if repository.publicKey == nil {
		return nil, nil, ErrNotFound
	}
	return repository.publicKey, repository.secret, nil
}

func (repository *MemoryRepository) PutServiceKey(_ context.Context, publicKey, sealedSecret []byte) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	repository.publicKey = publicKey
	repository.secret = sealedSecret
	return nil
}

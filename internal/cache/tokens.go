package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RefreshResult is the response of a completed refresh rotation, replayed to
// concurrent requests presenting the same old token.
type RefreshResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// AcquireRotationLock fails with ErrTokenReplayed while another request is
// rotating the same refresh token.
func (store *Store) AcquireRotationLock(ctx context.Context, tokenID string) error {
	acquired, err := store.client.SetNX(ctx, "rt_lock:"+tokenID, "1", 30*time.Second).Result()
	if err != nil {
		return err
	}
	if !acquired {
		return ErrTokenReplayed
	}
	return nil
}

func (store *Store) SaveRotationResult(ctx context.Context, tokenID string, result RefreshResult, ttl time.Duration) error {
	return store.saveJSON(ctx, "rt_result:"+tokenID, result, ttl)
}

func (store *Store) GetRotationResult(ctx context.Context, tokenID string) (*RefreshResult, error) {
	var result RefreshResult
	err := store.getJSON(ctx, "rt_result:"+tokenID, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (store *Store) RevokeAccessToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil
	}
	return store.client.Set(ctx, "revoked:"+tokenID, "1", ttl).Err()
}

func (store *Store) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	count, err := store.client.Exists(ctx, "revoked:"+tokenID).Result()
	return count > 0, err
}

func (store *Store) getString(ctx context.Context, key string) (string, error) {
	value, err := store.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	return value, err
}

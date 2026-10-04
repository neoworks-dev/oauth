package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	verificationCodeTTL = 10 * time.Minute
	emailVerifiedTTL    = 15 * time.Minute
	resetTokenTTL       = 10 * time.Minute
)

// SaveVerificationCode stores an emailed code scoped by purpose ("signup" or
// "reset") so a code for one purpose cannot satisfy another.
func (store *Store) SaveVerificationCode(ctx context.Context, purpose, email, code string) error {
	return store.client.Set(ctx, "verify:"+purpose+":"+email, code, verificationCodeTTL).Err()
}

func (store *Store) GetVerificationCode(ctx context.Context, purpose, email string) (string, error) {
	return store.getString(ctx, "verify:"+purpose+":"+email)
}

func (store *Store) DeleteVerificationCode(ctx context.Context, purpose, email string) error {
	return store.client.Del(ctx, "verify:"+purpose+":"+email).Err()
}

func (store *Store) MarkEmailVerified(ctx context.Context, email string) error {
	return store.client.Set(ctx, "verified:signup:"+email, "1", emailVerifiedTTL).Err()
}

// ConsumeEmailVerified reports whether the email was verified and clears the
// mark so it cannot seed a second signup.
func (store *Store) ConsumeEmailVerified(ctx context.Context, email string) (bool, error) {
	_, err := store.client.GetDel(ctx, "verified:signup:"+email).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	return err == nil, err
}

func (store *Store) SaveResetToken(ctx context.Context, token, email string) error {
	return store.client.Set(ctx, "reset_token:"+token, email, resetTokenTTL).Err()
}

func (store *Store) PeekResetToken(ctx context.Context, token string) (string, error) {
	return store.getString(ctx, "reset_token:"+token)
}

func (store *Store) ConsumeResetToken(ctx context.Context, token string) (string, error) {
	email, err := store.client.GetDel(ctx, "reset_token:"+token).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	return email, err
}

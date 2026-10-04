// Package cache keeps short-lived state in Redis: challenges, authorization
// codes, vault sessions, revocation marks, verification codes, handover
// sessions and rate limit counters.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrTokenReplayed = errors.New("refresh token already used")
)

type Store struct {
	client *redis.Client
}

// Config selects a single node or a Sentinel-managed master.
type Config struct {
	Addr          string
	SentinelAddrs []string
	MasterName    string
}

func ConfigFromEnv() Config {
	config := Config{Addr: os.Getenv("REDIS_URL"), MasterName: os.Getenv("REDIS_MASTER_NAME")}
	if config.Addr == "" {
		config.Addr = "127.0.0.1:6379"
	}
	for _, address := range strings.Split(os.Getenv("REDIS_SENTINEL_ADDRS"), ",") {
		trimmed := strings.TrimSpace(address)
		if trimmed != "" {
			config.SentinelAddrs = append(config.SentinelAddrs, trimmed)
		}
	}
	return config
}

func New(config Config) *Store {
	if len(config.SentinelAddrs) > 0 && config.MasterName != "" {
		return &Store{client: redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    config.MasterName,
			SentinelAddrs: config.SentinelAddrs,
		})}
	}
	return &Store{client: redis.NewClient(&redis.Options{Addr: config.Addr})}
}

func (store *Store) saveJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return store.client.Set(ctx, key, encoded, ttl).Err()
}

func (store *Store) getJSON(ctx context.Context, key string, destination any) error {
	encoded, err := store.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, destination)
}

func (store *Store) takeJSON(ctx context.Context, key string, destination any) error {
	encoded, err := store.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, destination)
}

// CountWithin increments a counter that expires window after its first hit and
// returns the new count.
func (store *Store) CountWithin(ctx context.Context, key string, window time.Duration) (int64, error) {
	count, err := store.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if count == 1 {
		err = store.client.Expire(ctx, key, window).Err()
	}
	return count, err
}

func (store *Store) Ping(ctx context.Context) error {
	return store.client.Ping(ctx).Err()
}

func marshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

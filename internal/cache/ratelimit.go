package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// hitScript counts a hit and starts the window on the first one, atomically.
var hitScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('PTTL', KEYS[1])}
`)

// Hit adds one to the key and returns the count inside the current window and
// how long the window still lasts.
func (store *Store) Hit(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	result, err := hitScript.Run(ctx, store.client, []string{key}, window.Milliseconds()).Int64Slice()
	if err != nil {
		return 0, 0, err
	}
	if len(result) != 2 {
		return 0, 0, fmt.Errorf("rate limit script returned %d values", len(result))
	}
	return result[0], time.Duration(result[1]) * time.Millisecond, nil
}

const usageRetention = 45 * 24 * time.Hour

func usageKey(clientID string, day time.Time) string {
	return "usage:" + clientID + ":" + day.UTC().Format("20060102")
}

// RecordUsage counts one call of the client today, and one refused call when
// limited. The api reads the same counters for the usage of an app.
func (store *Store) RecordUsage(ctx context.Context, clientID string, limited bool) error {
	key := usageKey(clientID, time.Now())
	pipeline := store.client.Pipeline()
	pipeline.HIncrBy(ctx, key, "requests", 1)
	if limited {
		pipeline.HIncrBy(ctx, key, "limited", 1)
	}
	pipeline.Expire(ctx, key, usageRetention)
	_, err := pipeline.Exec(ctx)
	return err
}

// UsageToday returns the calls and refused calls the client made today.
func (store *Store) UsageToday(ctx context.Context, clientID string) (int64, int64, error) {
	fields, err := store.client.HGetAll(ctx, usageKey(clientID, time.Now())).Result()
	if err != nil {
		return 0, 0, err
	}
	return parseCount(fields["requests"]), parseCount(fields["limited"]), nil
}

func parseCount(text string) int64 {
	count, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0
	}
	return count
}

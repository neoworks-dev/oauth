package cache

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func TestTheStoreAuthenticatesWithTheConfiguredPassword(t *testing.T) {
	server := miniredis.RunT(t)
	server.RequireAuth("secret")
	t.Setenv("REDIS_URL", server.Addr())
	t.Setenv("REDIS_PASSWORD", "secret")

	store := New(ConfigFromEnv())

	if err := store.Ping(t.Context()); err != nil {
		t.Fatalf("ping with the password: %v", err)
	}
}

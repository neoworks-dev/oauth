package store_test

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/testsupport"
)

var testSurreal *testsupport.Surreal

// TestMain starts an in-memory SurrealDB when the binary is available. Tests
// that need it skip when it is not.
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

func requireStore(t *testing.T) *store.Store {
	t.Helper()
	if testSurreal == nil {
		t.Skip("surreal binary not available")
	}
	return testSurreal.Store
}

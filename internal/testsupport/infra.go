// Package testsupport starts the infrastructure handler tests run against: an
// in-memory SurrealDB and an in-process Redis.
package testsupport

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/store"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// tables are declared schemaless; the real schema belongs to the api migrations.
var tables = []string{
	"user", "key_bundle", "device", "client", "refresh_token", "install", "certificate",
	"access_grant", "access_log", "node",
}

// Surreal is a running in-memory SurrealDB.
type Surreal struct {
	Store   *store.Store
	db      *surrealdb.DB
	process *exec.Cmd
}

// StartSurreal starts the surreal binary, or returns nil when it is not installed.
func StartSurreal() (*Surreal, error) {
	path, err := exec.LookPath("surreal")
	if err != nil {
		return nil, nil
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	process := exec.Command(path, "start", "memory", "--bind", address, "--user", "root", "--pass", "root", "--log", "error")
	if err := process.Start(); err != nil {
		return nil, err
	}
	db, err := connect("ws://" + address)
	if err != nil {
		_ = process.Process.Kill()
		return nil, err
	}
	return &Surreal{Store: store.New(db), db: db, process: process}, nil
}

func (surreal *Surreal) Stop() {
	_ = surreal.process.Process.Kill()
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func connect(url string) (*surrealdb.DB, error) {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		opened, err := tryConnect(url)
		if err == nil {
			return opened, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("surreal did not start")
}

func tryConnect(url string) (*surrealdb.DB, error) {
	ctx := context.Background()
	db, err := surrealdb.FromEndpointURLString(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := db.SignIn(ctx, surrealdb.Auth{Username: "root", Password: "root"}); err != nil {
		return nil, err
	}
	if err := db.Use(ctx, "test", "test"); err != nil {
		return nil, err
	}
	for _, table := range tables {
		if _, err := surrealdb.Query[any](ctx, db, "DEFINE TABLE "+table+" SCHEMALESS", nil); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// NewRedis starts an in-process Redis and a cache store connected to it.
func NewRedis(t testing.TB) (*miniredis.Miniredis, *cache.Store) {
	t.Helper()
	server := miniredis.RunT(t)
	return server, cache.New(cache.Config{Addr: server.Addr()})
}

// CreateClient registers an OAuth client, which the api migrations seed in production.
func (surreal *Surreal) CreateClient(clientID string, redirectURIs, clientScopes []string, autoGrant bool) error {
	_, err := surrealdb.Query[any](context.Background(), surreal.db, `
		CREATE $id CONTENT {
			name: $name, redirect_uris: $redirect_uris, scopes: $scopes,
			auto_grant_scopes: $auto_grant, public: true
		}`,
		map[string]any{
			"id": models.NewRecordID("client", clientID), "name": "Test " + clientID,
			"redirect_uris": redirectURIs, "scopes": clientScopes, "auto_grant": autoGrant,
		})
	return err
}

// Exec runs a statement against the test database.
func (surreal *Surreal) Exec(sql string, vars map[string]any) error {
	_, err := surrealdb.Query[any](context.Background(), surreal.db, sql, vars)
	return err
}

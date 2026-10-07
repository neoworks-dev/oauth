// Package testsupport starts the infrastructure handler tests run against: an
// in-memory SurrealDB and an in-process Redis.
package testsupport

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
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
	"user", "key_bundle", "identity_key", "device", "client", "refresh_token", "install", "certificate",
	"access_grant", "access_log", "node", "registry_schema", "registry_schema_version",
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
	if err := defineSchema(ctx, db); err != nil {
		return nil, err
	}
	return db, nil
}

// defineSchema loads the api migrations when NEOWORKS_MIGRATIONS points at them,
// which checks the stores against the real schema; otherwise it declares the
// tables schemaless.
func defineSchema(ctx context.Context, db *surrealdb.DB) error {
	directory := migrationsDirectory()
	if directory != "" {
		return applyMigrations(ctx, db, directory)
	}
	for _, table := range tables {
		if _, err := surrealdb.Query[any](ctx, db, "DEFINE TABLE "+table+" SCHEMALESS", nil); err != nil {
			return err
		}
	}
	return nil
}

// migrationsDirectory is NEOWORKS_MIGRATIONS, the api migrations to test the
// stores against. Without it the tables are schemaless.
func migrationsDirectory() string {
	return os.Getenv("NEOWORKS_MIGRATIONS")
}

func applyMigrations(ctx context.Context, db *surrealdb.DB, directory string) error {
	files, err := filepath.Glob(filepath.Join(directory, "*.surql"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no migrations found in %s", directory)
	}
	sort.Strings(files)
	for _, file := range files {
		script, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if err := runScript(ctx, db, file, string(script)); err != nil {
			return err
		}
	}
	return nil
}

func runScript(ctx context.Context, db *surrealdb.DB, name, script string) error {
	results, err := surrealdb.Query[any](ctx, db, script, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, result := range *results {
		if result.Error != nil {
			return fmt.Errorf("%s: %v", name, result.Error)
		}
	}
	return nil
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

// TestDescriptor is the node descriptor test collections are published with: a
// container whose title is field 1.
const TestDescriptor = `{"descriptorVersion":1,"models":[{"name":"Folder","fields":[` +
	`{"ordinal":1,"name":"name","container":{"kind":"singular","nullable":false},` +
	`"value":{"kind":"scalar","scalar":"string"},"required":true,"constraints":{}}]}],"enums":[],` +
	`"nodes":[{"kind":"container","model":"Folder","facets":[{"name":"default","tag":1,"fields":[1]}],` +
	`"searchable":[],"title":1,"timeRange":null}]}`

// PublishCollections publishes each collection as a node schema with
// TestDescriptor. Publishing again changes nothing.
func (surreal *Surreal) PublishCollections(collections []string) error {
	for _, collection := range collections {
		scope, name, _ := strings.Cut(strings.TrimPrefix(collection, "@"), "/")
		key := scope + "_" + name
		_, err := surrealdb.Query[any](context.Background(), surreal.db, `
			UPSERT $schema SET scope = $scope, name = $name, title = $title, description = 'Test schema',
				latest_version = '1.0.0', owner = user:publisher;
			UPSERT $version SET schema = $schema, version = '1.0.0', descriptor = $descriptor;`,
			map[string]any{
				"schema": models.NewRecordID("registry_schema", key), "version": models.NewRecordID("registry_schema_version", key),
				"scope": scope, "name": name, "title": "Test " + name, "descriptor": TestDescriptor,
			})
		if err != nil {
			return err
		}
	}
	return nil
}

// Exec runs a statement against the test database.
func (surreal *Surreal) Exec(sql string, vars map[string]any) error {
	_, err := surrealdb.Query[any](context.Background(), surreal.db, sql, vars)
	return err
}

// DB exposes the raw connection, for repositories that bring their own schema.
func (surreal *Surreal) DB() *surrealdb.DB {
	return surreal.db
}

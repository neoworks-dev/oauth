package store

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

var testStore *Store

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// TestMain starts an in-memory SurrealDB when the binary is available. Tests
// that need it skip when testStore is nil.
func TestMain(m *testing.M) {
	surrealPath, err := exec.LookPath("surreal")
	if err != nil {
		os.Exit(m.Run())
	}
	port, err := freePort()
	if err != nil {
		panic(err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	command := exec.Command(surrealPath, "start", "memory", "--bind", address, "--user", "root", "--pass", "root", "--log", "error")
	if err := command.Start(); err != nil {
		panic(err)
	}
	testStore = connectWhenReady("ws://" + address)
	code := m.Run()
	_ = command.Process.Kill()
	os.Exit(code)
}

func connectWhenReady(url string) *Store {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		opened, err := Open(context.Background(), url, "root", "root", "test", "test")
		if err == nil {
			defineTestTables(opened)
			return opened
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

func requireStore(t *testing.T) *Store {
	t.Helper()
	if testStore == nil {
		t.Skip("surreal binary not available")
	}
	return testStore
}

// defineTestTables declares the tables schemaless; the real schema belongs to
// the api migrations.
func defineTestTables(opened *Store) {
	tables := []string{
		"user", "key_bundle", "device", "client", "refresh_token", "install", "certificate",
		"access_grant", "access_log", "node",
	}
	for _, table := range tables {
		if err := execute(context.Background(), opened, "DEFINE TABLE "+table+" SCHEMALESS", nil); err != nil {
			panic(err)
		}
	}
}

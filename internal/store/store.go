// Package store reads and writes the oauth service's SurrealDB tables.
package store

import (
	"context"
	"errors"
	"fmt"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrEmailTaken = errors.New("email already registered")
	ErrConflict   = errors.New("version conflict")
	ErrRevoked    = errors.New("revoked")
)

type Store struct {
	db *surrealdb.DB
}

func Open(ctx context.Context, url, user, password, namespace, database string) (*Store, error) {
	db, err := surrealdb.FromEndpointURLString(ctx, url)
	if err != nil {
		return nil, err
	}
	_, err = db.SignIn(ctx, surrealdb.Auth{Username: user, Password: password})
	if err != nil {
		return nil, err
	}
	err = db.Use(ctx, namespace, database)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func New(db *surrealdb.DB) *Store {
	return &Store{db: db}
}

func recordID(table, id string) models.RecordID {
	return models.NewRecordID(table, id)
}

// rows runs a query and returns the rows of its last statement.
func rows[Row any](ctx context.Context, store *Store, sql string, vars map[string]any) ([]Row, error) {
	results, err := surrealdb.Query[[]Row](ctx, store.db, sql, vars)
	if err != nil {
		return nil, err
	}
	if len(*results) == 0 {
		return nil, nil
	}
	return (*results)[len(*results)-1].Result, nil
}

// transactionRows runs a BEGIN ... COMMIT query and returns the rows of the
// statement before COMMIT.
func transactionRows[Row any](ctx context.Context, store *Store, sql string, vars map[string]any) ([]Row, error) {
	results, err := surrealdb.Query[[]Row](ctx, store.db, sql, vars)
	if err != nil {
		return nil, err
	}
	if len(*results) < 2 {
		return nil, nil
	}
	return (*results)[len(*results)-2].Result, nil
}

func firstRow[Row any](ctx context.Context, store *Store, sql string, vars map[string]any) (*Row, error) {
	found, err := rows[Row](ctx, store, sql, vars)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNotFound
	}
	return &found[0], nil
}

func execute(ctx context.Context, store *Store, sql string, vars map[string]any) error {
	_, err := surrealdb.Query[any](ctx, store.db, sql, vars)
	return err
}

func wrapQueryError(operation string, err error) error {
	return fmt.Errorf("%s: %w", operation, err)
}

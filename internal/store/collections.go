package store

import (
	"context"
	"slices"
)

// CollectionSchema is what the registry publishes for a collection: its title
// and the node descriptor of its latest version.
type CollectionSchema struct {
	Collection string `json:"collection"`
	Title      string `json:"title"`
	Descriptor string `json:"descriptor"`
}

// CollectionSchemas returns the schemas of the given collections whose latest
// version describes Neoworks nodes. A collection missing from the result is not
// a published node schema.
func (store *Store) CollectionSchemas(ctx context.Context, collections []string) (map[string]CollectionSchema, error) {
	found, err := rows[CollectionSchema](ctx, store, `
		SELECT string::concat('@', scope, '/', name) AS collection, title,
			(SELECT VALUE descriptor FROM registry_schema_version
				WHERE schema = $parent.id AND version = $parent.latest_version)[0] AS descriptor
		FROM registry_schema WHERE string::concat('@', scope, '/', name) IN $collections`,
		map[string]any{"collections": collections})
	if err != nil {
		return nil, err
	}
	schemas := map[string]CollectionSchema{}
	for _, schema := range found {
		if schema.Descriptor != "" {
			schemas[schema.Collection] = schema
		}
	}
	return schemas, nil
}

// UserCollections lists the collections of the nodes the user owns or holds an
// active user grant on.
func (store *Store) UserCollections(ctx context.Context, userID string) ([]string, error) {
	owned, err := rows[string](ctx, store,
		`SELECT VALUE collection FROM node WHERE owner_id = $user AND kind = 'root'`,
		map[string]any{"user": userID})
	if err != nil {
		return nil, err
	}
	shared, err := rows[string](ctx, store, `
		SELECT VALUE type::record('node', node_id).collection FROM access_grant
		WHERE principal_type = 'user' AND principal_id = $user AND revoked_at = NONE`,
		map[string]any{"user": userID})
	if err != nil {
		return nil, err
	}
	collections := []string{}
	for _, collection := range append(owned, shared...) {
		if !slices.Contains(collections, collection) {
			collections = append(collections, collection)
		}
	}
	return collections, nil
}

// RootCollections lists the collections in which the user owns a root.
func (store *Store) RootCollections(ctx context.Context, userID string) ([]string, error) {
	return rows[string](ctx, store,
		`SELECT VALUE collection FROM node WHERE owner_id = $user AND kind = 'root' AND deleted = false`,
		map[string]any{"user": userID})
}

package store

import (
	"context"
	"errors"
	"time"

	"github.com/neoworks/oauth/internal/scopes"
)

// Authorization is a user's standing authorization of a client: the scopes the
// client holds and when the user first and most recently approved it.
type Authorization struct {
	Scopes            []string  `json:"scopes"`
	FirstAuthorizedAt time.Time `json:"created_at"`
	LastAuthorizedAt  time.Time `json:"updated_at"`
}

// GetAuthorization returns the user's authorization of the client, or
// ErrNotFound when the user never authorized it or switched it off.
func (store *Store) GetAuthorization(ctx context.Context, userID, clientID string) (*Authorization, error) {
	return firstRow[Authorization](ctx, store, `
		SELECT scopes, created_at, updated_at FROM grant
		WHERE user = $user AND client = $client AND enabled = true LIMIT 1`,
		map[string]any{"user": recordID("user", userID), "client": recordID("client", clientID)})
}

// RecordAuthorization stores an approval. The client keeps the access it holds
// in collections the approval does not mention, so those scopes stay.
func (store *Store) RecordAuthorization(ctx context.Context, userID, clientID string, approved []string) error {
	held, err := store.scopesAfterApproval(ctx, userID, clientID, approved)
	if err != nil {
		return err
	}
	return execute(ctx, store, `
		UPSERT grant SET user = $user, client = $client, scopes = $scopes, enabled = true,
			updated_at = time::now()
		WHERE user = $user AND client = $client`,
		map[string]any{"user": recordID("user", userID), "client": recordID("client", clientID), "scopes": held})
}

func (store *Store) scopesAfterApproval(ctx context.Context, userID, clientID string, approved []string) ([]string, error) {
	previous, err := store.GetAuthorization(ctx, userID, clientID)
	if errors.Is(err, ErrNotFound) {
		return approved, nil
	}
	if err != nil {
		return nil, err
	}
	return scopes.Retain(previous.Scopes, approved), nil
}

// ListClientInstalls lists the user's installs of the client, oldest first.
func (store *Store) ListClientInstalls(ctx context.Context, userID, clientID string) ([]Install, error) {
	return rows[Install](ctx, store, `
		SELECT `+installColumns+` FROM install
		WHERE user = $user AND client = $client ORDER BY created_at ASC`,
		map[string]any{"user": recordID("user", userID), "client": recordID("client", clientID)})
}

// HeldAccess is access one of the user's installs of a client holds on a node.
type HeldAccess struct {
	Collection string `json:"collection"`
	NodeID     string `json:"node_id"`
	Role       string `json:"role"`
	InstallID  string `json:"install_id"`
}

const heldAccessColumns = `type::record('node', node_id).collection AS collection, node_id, role, principal_id AS install_id`

// ListClientAccess lists the active access the user's installs of the client
// hold on nodes.
func (store *Store) ListClientAccess(ctx context.Context, userID, clientID string) ([]HeldAccess, error) {
	return rows[HeldAccess](ctx, store, `
		SELECT `+heldAccessColumns+` FROM access_grant
		WHERE principal_type = 'install' AND revoked_at = NONE
			AND principal_id IN (SELECT VALUE record::id(id) FROM install WHERE user = $user AND client = $client)`,
		map[string]any{"user": recordID("user", userID), "client": recordID("client", clientID)})
}

// RevokeClientCollection revokes all access the user's installs of the client
// hold in a collection, flags the nodes for key rotation and drops the
// collection's scopes from the authorization. Like revoking an install, it
// appends nothing to the access logs.
func (store *Store) RevokeClientCollection(ctx context.Context, userID, clientID, collection string) error {
	access, err := store.ListClientAccess(ctx, userID, clientID)
	if err != nil {
		return err
	}
	nodeIDs := []string{}
	for _, held := range access {
		if held.Collection == collection {
			nodeIDs = append(nodeIDs, held.NodeID)
		}
	}
	authorization, err := store.GetAuthorization(ctx, userID, clientID)
	if err != nil {
		return err
	}
	return execute(ctx, store, `
		BEGIN TRANSACTION;
		LET $grants = (SELECT node_id, facets FROM access_grant
			WHERE principal_type = 'install' AND revoked_at = NONE AND node_id IN $node_ids
				AND principal_id IN (SELECT VALUE record::id(id) FROM install WHERE user = $user AND client = $client));
		UPDATE access_grant SET revoked_at = time::now(), seq = fn::next_seq()
			WHERE principal_type = 'install' AND revoked_at = NONE AND node_id IN $node_ids
				AND principal_id IN (SELECT VALUE record::id(id) FROM install WHERE user = $user AND client = $client);
		FOR $grant IN $grants {
			fn::flag_for_rotation($grant.node_id, $grant.facets = NONE);
		};
		UPDATE grant SET scopes = $scopes, updated_at = time::now() WHERE user = $user AND client = $client;
		COMMIT TRANSACTION;`,
		map[string]any{
			"user": recordID("user", userID), "client": recordID("client", clientID),
			"node_ids": nodeIDs, "scopes": scopes.WithoutCollection(authorization.Scopes, collection),
		})
}

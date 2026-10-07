package store

import (
	"context"
	"time"
)

// Node is the stored form of a tree node (contract section 4). Binary values are
// base64url strings. Content is one message with a LEN field per facet tag whose
// body is that facet's ciphertext; roots have none. Blob is the node's blob
// descriptor, passed through opaque.
type Node struct {
	ID            string         `json:"id"`
	ParentID      string         `json:"parent_id"`
	OwnerID       string         `json:"owner_id"`
	Collection    string         `json:"collection"`
	Kind          string         `json:"kind"`
	Epoch         uint32         `json:"epoch"`
	WrappedKey    string         `json:"wrapped_key"`
	Content       string         `json:"content"`
	Blob          map[string]any `json:"blob"`
	Deleted       bool           `json:"deleted"`
	BaseSeq       uint64         `json:"base_seq"`
	Seq           uint64         `json:"seq"`
	AuthorType    string         `json:"author_type"`
	AuthorID      string         `json:"author_id"`
	CertID        string         `json:"cert_id"`
	Signature     string         `json:"signature"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	NeedsRotation bool           `json:"needs_rotation"`
}

const nodeColumns = `record::id(id) AS id, parent_id, owner_id, collection, kind, epoch,
	wrapped_key, content, blob, deleted, base_seq, seq, author_type, author_id, cert_id,
	signature, created_at, updated_at, needs_rotation`

func nodeFields(node Node) map[string]any {
	fields := map[string]any{
		"id":             node.ID,
		"owner_id":       node.OwnerID,
		"collection":     node.Collection,
		"kind":           node.Kind,
		"epoch":          node.Epoch,
		"content":        node.Content,
		"deleted":        node.Deleted,
		"base_seq":       node.BaseSeq,
		"seq":            node.Seq,
		"author_type":    node.AuthorType,
		"author_id":      node.AuthorID,
		"signature":      node.Signature,
		"created_at":     node.CreatedAt,
		"updated_at":     node.UpdatedAt,
		"needs_rotation": false,
	}
	if node.ParentID != "" {
		fields["parent_id"] = node.ParentID
	}
	if node.WrappedKey != "" {
		fields["wrapped_key"] = node.WrappedKey
	}
	if node.Blob != nil {
		fields["blob"] = node.Blob
	}
	if node.CertID != "" {
		fields["cert_id"] = node.CertID
	}
	return fields
}

// ListStructure returns the user's non-deleted root and container nodes, which
// is all the consent screen needs to let the user pick subtrees.
func (store *Store) ListStructure(ctx context.Context, userID string) ([]Node, error) {
	return rows[Node](ctx, store, `
		SELECT `+nodeColumns+` FROM node
		WHERE owner_id = $owner AND kind IN ['root', 'container'] AND deleted = false`,
		map[string]any{"owner": userID})
}

// ListOwnerGrants returns the user's active whole-node grants as a user
// principal: their own roots and what other people shared with them.
func (store *Store) ListOwnerGrants(ctx context.Context, userID string) ([]AccessGrant, error) {
	return rows[AccessGrant](ctx, store, `
		SELECT `+accessGrantColumns+` FROM access_grant
		WHERE principal_type = 'user' AND principal_id = $user AND revoked_at = NONE AND facets = NONE`,
		map[string]any{"user": userID})
}

// ListSharedStructure returns the root and container nodes other people own
// that the user can read as a whole through an active user grant, together with
// the containers beneath them. Facet-only grants are not included.
func (store *Store) ListSharedStructure(ctx context.Context, userID string) ([]Node, error) {
	grantedNodeIDs, err := rows[string](ctx, store, `
		SELECT VALUE node_id FROM access_grant
		WHERE principal_type = 'user' AND principal_id = $user AND revoked_at = NONE AND facets = NONE`,
		map[string]any{"user": userID})
	if err != nil || len(grantedNodeIDs) == 0 {
		return nil, err
	}
	return rows[Node](ctx, store, `
		SELECT `+nodeColumns+` FROM node
		WHERE owner_id != $user AND kind IN ['root', 'container'] AND deleted = false
		AND (record::id(id) IN $granted OR ancestors CONTAINSANY $granted)`,
		map[string]any{"user": userID, "granted": grantedNodeIDs})
}

// NodeOwnership is the part of a node the consent check needs.
type NodeOwnership struct {
	ID         string   `json:"id"`
	OwnerID    string   `json:"owner_id"`
	Collection string   `json:"collection"`
	Kind       string   `json:"kind"`
	Epoch      uint32   `json:"epoch"`
	Ancestors  []string `json:"ancestors"`
}

// WholeNodeRole returns the highest role the user holds as a whole-node grant
// on the node or one of its ancestors, or "" when the user holds none.
func (store *Store) WholeNodeRole(ctx context.Context, userID string, node NodeOwnership) (string, error) {
	roles, err := rows[string](ctx, store, `
		SELECT VALUE role FROM access_grant
		WHERE principal_type = 'user' AND principal_id = $user AND revoked_at = NONE AND facets = NONE
		AND (node_id = $node OR node_id IN $ancestors)`,
		map[string]any{"user": userID, "node": node.ID, "ancestors": node.Ancestors})
	if err != nil {
		return "", err
	}
	best := ""
	for _, role := range roles {
		if role == "write" || best == "" {
			best = role
		}
	}
	return best, nil
}

func (store *Store) GetNodeOwnerships(ctx context.Context, nodeIDs []string) ([]NodeOwnership, error) {
	return rows[NodeOwnership](ctx, store, `
		SELECT record::id(id) AS id, owner_id, collection, kind, epoch, ancestors FROM node
		WHERE record::id(id) IN $node_ids AND deleted = false`,
		map[string]any{"node_ids": nodeIDs})
}

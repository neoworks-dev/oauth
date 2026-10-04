package store

import (
	"context"
	"time"
)

// NodeFacet is one encrypted facet of a node. Ciphertext is base64url.
type NodeFacet struct {
	Facet      uint32 `json:"facet"`
	Ciphertext string `json:"ciphertext"`
}

// Node is the stored form of a tree node (contract section 4). Binary values are
// base64url strings. Blob is the node's blob descriptor, passed through opaque.
type Node struct {
	ID            string         `json:"id"`
	ParentID      string         `json:"parent_id"`
	OwnerID       string         `json:"owner_id"`
	Collection    string         `json:"collection"`
	Kind          string         `json:"kind"`
	Epoch         uint32         `json:"epoch"`
	WrappedKey    string         `json:"wrapped_key"`
	Content       []NodeFacet    `json:"content"`
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

// ListOwnerGrants returns the user's active grants as a user principal.
func (store *Store) ListOwnerGrants(ctx context.Context, userID string) ([]AccessGrant, error) {
	return rows[AccessGrant](ctx, store, `
		SELECT `+accessGrantColumns+` FROM access_grant
		WHERE principal_type = 'user' AND principal_id = $user AND revoked_at = NONE`,
		map[string]any{"user": userID})
}

// NodeOwnership is the part of a node the consent check needs.
type NodeOwnership struct {
	ID         string `json:"id"`
	OwnerID    string `json:"owner_id"`
	Collection string `json:"collection"`
	Kind       string `json:"kind"`
	Epoch      uint32 `json:"epoch"`
}

func (store *Store) GetNodeOwnerships(ctx context.Context, nodeIDs []string) ([]NodeOwnership, error) {
	return rows[NodeOwnership](ctx, store, `
		SELECT record::id(id) AS id, owner_id, collection, kind, epoch FROM node
		WHERE record::id(id) IN $node_ids AND deleted = false`,
		map[string]any{"node_ids": nodeIDs})
}

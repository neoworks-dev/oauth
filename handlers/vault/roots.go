package vault

import (
	"net/http"
	"slices"
	"time"

	"github.com/neoworks/oauth/internal/ids"
	"github.com/neoworks/oauth/internal/scopes"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/wire"
)

// rootPayload is a new collection root together with the owner's grant on it.
type rootPayload struct {
	Node  nodePayload  `json:"node"`
	Grant grantPayload `json:"grant"`
}

// newRoot is a checked root and owner grant, ready to store.
type newRoot struct {
	Node  store.Node
	Grant store.AccessGrant
}

// checkedRoot verifies a root the user created and their signed grant on it.
func checkedRoot(userID string, root rootPayload, signPub []byte, now time.Time) (newRoot, error) {
	node, err := rootNode(userID, root.Node, now)
	if err != nil {
		return newRoot{}, err
	}
	if root.Grant.NodeID != node.ID {
		return newRoot{}, errInvalidPayload
	}
	grant, err := checkedOwnerGrant(userID, node, root.Grant, signPub, now)
	if err != nil {
		return newRoot{}, err
	}
	return newRoot{Node: node, Grant: grant}, nil
}

// rootNode checks a root: owned and authored by the user, first version, in a
// collection, and without parent, key, content, blob or target.
func rootNode(userID string, node nodePayload, now time.Time) (store.Node, error) {
	if !ids.IsLowercaseUUIDv4(node.ID) || node.OwnerID != userID || node.Kind != "root" {
		return store.Node{}, errInvalidPayload
	}
	hasPayload := node.WrappedKey != nil || node.Content != "" || node.Blob != nil || node.TargetID != nil || node.TargetRole != nil
	if node.ParentID != nil || hasPayload || node.Deleted || node.BaseSeq != 0 {
		return store.Node{}, errInvalidPayload
	}
	if node.AuthorType != "user" || node.AuthorID != userID || node.CertID != nil {
		return store.Node{}, errInvalidPayload
	}
	if !scopes.IsCollection(node.Collection) || node.Epoch == 0 {
		return store.Node{}, errInvalidPayload
	}
	if _, err := decodeSized(node.Signature, signatureBytes); err != nil {
		return store.Node{}, err
	}
	return store.Node{
		ID: node.ID, OwnerID: userID, Collection: node.Collection, Kind: "root", Epoch: node.Epoch,
		AuthorType: "user", AuthorID: userID, Signature: node.Signature, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// checkedOwnerGrant requires the user's own write grant on the whole root, signed
// by them as the genesis entry of the root's access log.
func checkedOwnerGrant(userID string, node store.Node, grant grantPayload, signPub []byte, now time.Time) (store.AccessGrant, error) {
	isOwnerWrite := grant.PrincipalType == "user" && grant.PrincipalID == userID && grant.Role == "write"
	isSelfGranted := grant.GrantedByType == "user" && grant.GrantedByID == userID
	if !isOwnerWrite || !isSelfGranted || grant.Facets != nil || grant.CertID != nil || grant.Epoch != node.Epoch {
		return store.AccessGrant{}, errInvalidPayload
	}
	isGenesis := grant.LogIndex == 0 && grant.PrevHash == wire.EncodeBase64URL(wire.GenesisPrevHash)
	if !isGenesis {
		return store.AccessGrant{}, errInvalidPayload
	}
	return verifiedGrantEntry(grant, signPub, now)
}

// collectionsPublished requires every collection the scopes name to be a
// published node schema. It writes the HTTP error itself.
func (server *Server) collectionsPublished(response http.ResponseWriter, request *http.Request, requested []string) bool {
	collections := scopes.Collections(requested)
	if len(collections) == 0 {
		return true
	}
	schemas, err := server.store.CollectionSchemas(request.Context(), collections)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return false
	}
	if len(schemas) != len(collections) {
		writeError(response, http.StatusBadRequest, "unknown_collection")
		return false
	}
	return true
}

// verifiedNewRoots checks the roots a consent creates: at most one per approved
// collection, and only where the user owns no root yet.
func (server *Server) verifiedNewRoots(request *http.Request, consent consentContext, roots []rootPayload) ([]newRoot, error) {
	existing, err := server.store.RootCollections(request.Context(), consent.userID)
	if err != nil {
		return nil, err
	}
	roles := scopes.CollectionRoles(consent.approved)
	checked := make([]newRoot, 0, len(roots))
	for _, root := range roots {
		collection := root.Node.Collection
		if roles[collection] == "" || slices.Contains(existing, collection) {
			return nil, errInvalidPayload
		}
		verified, err := checkedRoot(consent.userID, root, consent.signPub, consent.now)
		if err != nil {
			return nil, err
		}
		existing = append(existing, collection)
		checked = append(checked, verified)
	}
	return checked, nil
}

func rootNodes(roots []newRoot) []store.Node {
	nodes := make([]store.Node, 0, len(roots))
	for _, root := range roots {
		nodes = append(nodes, root.Node)
	}
	return nodes
}

func rootGrants(roots []newRoot) []store.AccessGrant {
	grants := make([]store.AccessGrant, 0, len(roots))
	for _, root := range roots {
		grants = append(grants, root.Grant)
	}
	return grants
}

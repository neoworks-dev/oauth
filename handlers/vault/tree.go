package vault

import (
	"net/http"

	"github.com/neoworks/oauth/internal/store"
)

type treeNodeView struct {
	ID         string         `json:"id"`
	OwnerID    string         `json:"ownerId"`
	OwnerEmail string         `json:"ownerEmail,omitempty"`
	ParentID   *string        `json:"parentId"`
	Collection string         `json:"collection"`
	Kind       string         `json:"kind"`
	Epoch      uint32         `json:"epoch"`
	WrappedKey *string        `json:"wrappedKey"`
	Content    []facetPayload `json:"content"`
}

type ownerGrantView struct {
	NodeID      string `json:"nodeId"`
	Role        string `json:"role"`
	Epoch       uint32 `json:"epoch"`
	WrappedKeys string `json:"wrappedKeys"`
}

type logHeadView struct {
	Index     uint64 `json:"index"`
	EntryHash string `json:"entryHash"`
}

// handleTree returns the user's root and container nodes and those shared with
// them, the user's grants
// that unlock the roots and each node's access log head, which is what the
// consent screen needs to offer narrower selections and sign install grants.
func (server *Server) handleTree(response http.ResponseWriter, request *http.Request) {
	userID := sessionFrom(request).Session.UserID
	nodes, err := server.treeNodes(request, userID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	grants, err := server.store.ListOwnerGrants(request.Context(), userID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	heads, err := server.store.ListLogHeads(request.Context(), nodeIDsOf(nodes))
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"nodes":  server.treeNodeViews(request, userID, nodes),
		"grants": ownerGrantViews(grants),
		"heads":  logHeadViews(heads),
	})
}

// treeNodes is the user's own structure followed by the structure other people
// shared with them.
func (server *Server) treeNodes(request *http.Request, userID string) ([]store.Node, error) {
	own, err := server.store.ListStructure(request.Context(), userID)
	if err != nil {
		return nil, err
	}
	shared, err := server.store.ListSharedStructure(request.Context(), userID)
	if err != nil {
		return nil, err
	}
	return append(own, shared...), nil
}

func nodeIDsOf(nodes []store.Node) []string {
	nodeIDs := make([]string, 0, len(nodes))
	for _, node := range nodes {
		nodeIDs = append(nodeIDs, node.ID)
	}
	return nodeIDs
}

func logHeadViews(heads map[string]store.LogHead) map[string]logHeadView {
	views := make(map[string]logHeadView, len(heads))
	for nodeID, head := range heads {
		views[nodeID] = logHeadView{Index: head.Index, EntryHash: head.EntryHash}
	}
	return views
}

func (server *Server) treeNodeViews(request *http.Request, userID string, nodes []store.Node) []treeNodeView {
	ownerEmails := server.ownerEmails(request, userID, nodes)
	views := make([]treeNodeView, 0, len(nodes))
	for _, node := range nodes {
		view := treeNodeViewOf(node)
		view.OwnerEmail = ownerEmails[node.OwnerID]
		views = append(views, view)
	}
	return views
}

// ownerEmails names the people who own the shared nodes, so the consent screen
// can say whose calendar or contacts are being passed on.
func (server *Server) ownerEmails(request *http.Request, userID string, nodes []store.Node) map[string]string {
	emails := map[string]string{}
	for _, node := range nodes {
		_, known := emails[node.OwnerID]
		if node.OwnerID == userID || known {
			continue
		}
		owner, err := server.store.GetUserByID(request.Context(), node.OwnerID)
		if err == nil {
			emails[node.OwnerID] = owner.Email
		}
	}
	return emails
}

func treeNodeViewOf(node store.Node) treeNodeView {
	view := treeNodeView{ID: node.ID, OwnerID: node.OwnerID, Collection: node.Collection, Kind: node.Kind, Epoch: node.Epoch}
	if node.ParentID != "" {
		parentID := node.ParentID
		view.ParentID = &parentID
	}
	if node.WrappedKey != "" {
		wrappedKey := node.WrappedKey
		view.WrappedKey = &wrappedKey
	}
	for _, facet := range node.Content {
		view.Content = append(view.Content, facetPayload{Facet: facet.Facet, Ciphertext: facet.Ciphertext})
	}
	return view
}

func ownerGrantViews(grants []store.AccessGrant) []ownerGrantView {
	views := make([]ownerGrantView, 0, len(grants))
	for _, grant := range grants {
		views = append(views, ownerGrantView{
			NodeID: grant.NodeID, Role: grant.Role, Epoch: grant.Epoch, WrappedKeys: grant.WrappedKeys,
		})
	}
	return views
}

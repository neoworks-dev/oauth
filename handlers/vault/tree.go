package vault

import (
	"net/http"

	"github.com/neoworks/oauth/internal/store"
)

type treeNodeView struct {
	ID         string         `json:"id"`
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

// handleTree returns the user's root and container nodes and the owner grants
// that unlock the roots, which is what the consent screen needs to offer
// narrower selections.
func (server *Server) handleTree(response http.ResponseWriter, request *http.Request) {
	userID := sessionFrom(request).Session.UserID
	nodes, err := server.store.ListStructure(request.Context(), userID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	grants, err := server.store.ListOwnerGrants(request.Context(), userID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"nodes":  treeNodeViews(nodes),
		"grants": ownerGrantViews(grants),
	})
}

func treeNodeViews(nodes []store.Node) []treeNodeView {
	views := make([]treeNodeView, 0, len(nodes))
	for _, node := range nodes {
		views = append(views, treeNodeViewOf(node))
	}
	return views
}

func treeNodeViewOf(node store.Node) treeNodeView {
	view := treeNodeView{ID: node.ID, Collection: node.Collection, Kind: node.Kind, Epoch: node.Epoch}
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

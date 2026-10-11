package vault

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/neoworks/oauth/internal/scopes"
	"github.com/neoworks/oauth/internal/store"
)

// historyView is what the signed-in user earlier authorized for an app. It is
// built only from the session user's own rows.
type historyView struct {
	FirstAuthorizedAt time.Time `json:"firstAuthorizedAt"`
	LastAuthorizedAt  time.Time `json:"lastAuthorizedAt"`
	// Scopes are the scopes the app holds now.
	Scopes   []string         `json:"scopes"`
	Installs []historyInstall `json:"installs"`
	// Access is the access the app's installs hold on nodes.
	Access []historyAccess `json:"access"`
}

type historyInstall struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"createdAt"`
	RevokedAt *time.Time `json:"revokedAt"`
}

type historyAccess struct {
	Collection string `json:"collection"`
	NodeID     string `json:"nodeId"`
	Role       string `json:"role"`
	InstallID  string `json:"installId"`
}

// historyFor returns the session user's history with the client, or nil when
// nobody is signed in or the user never authorized the client.
func (server *Server) historyFor(request *http.Request, clientID string) (*historyView, error) {
	current, signedIn := server.loadSession(request)
	if !signedIn {
		return nil, nil
	}
	userID := current.Session.UserID
	authorization, err := server.store.GetAuthorization(request.Context(), userID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	installs, err := server.store.ListClientInstalls(request.Context(), userID, clientID)
	if err != nil {
		return nil, err
	}
	access, err := server.store.ListClientAccess(request.Context(), userID, clientID)
	if err != nil {
		return nil, err
	}
	return &historyView{
		FirstAuthorizedAt: authorization.FirstAuthorizedAt,
		LastAuthorizedAt:  authorization.LastAuthorizedAt,
		Scopes:            authorization.Scopes,
		Installs:          historyInstalls(installs),
		Access:            historyAccessRows(access),
	}, nil
}

func historyInstalls(installs []store.Install) []historyInstall {
	views := make([]historyInstall, 0, len(installs))
	for _, install := range installs {
		views = append(views, historyInstall{ID: install.ID, Name: install.Name, CreatedAt: install.CreatedAt, RevokedAt: install.RevokedAt})
	}
	return views
}

func historyAccessRows(access []store.HeldAccess) []historyAccess {
	views := make([]historyAccess, 0, len(access))
	for _, held := range access {
		views = append(views, historyAccess{Collection: held.Collection, NodeID: held.NodeID, Role: held.Role, InstallID: held.InstallID})
	}
	return views
}

// challengeCollections are the collections the request and the earlier
// authorization name, once each.
func challengeCollections(requested []string, history *historyView) []string {
	collections := scopes.Collections(requested)
	if history == nil {
		return collections
	}
	for _, collection := range scopes.Collections(history.Scopes) {
		if !slices.Contains(collections, collection) {
			collections = append(collections, collection)
		}
	}
	for _, held := range history.Access {
		if !slices.Contains(collections, held.Collection) {
			collections = append(collections, held.Collection)
		}
	}
	return collections
}

// handleRevokeKept revokes the access an app keeps in a collection it no
// longer asks for.
func (server *Server) handleRevokeKept(response http.ResponseWriter, request *http.Request) {
	var body struct {
		LoginChallenge string `json:"loginChallenge"`
		Collection     string `json:"collection"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	challenge, err := server.state.GetLoginChallenge(request.Context(), body.LoginChallenge)
	if err != nil {
		writeError(response, http.StatusNotFound, "challenge_not_found")
		return
	}
	if slices.Contains(scopes.Collections(challenge.Scopes), body.Collection) {
		writeError(response, http.StatusBadRequest, "collection_requested")
		return
	}
	userID := sessionFrom(request).Session.UserID
	authorization, err := server.store.GetAuthorization(request.Context(), userID, challenge.ClientID)
	if err != nil || !slices.Contains(scopes.Collections(authorization.Scopes), body.Collection) {
		writeError(response, http.StatusNotFound, "access_not_found")
		return
	}
	if err := server.store.RevokeClientCollection(request.Context(), userID, challenge.ClientID, body.Collection); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

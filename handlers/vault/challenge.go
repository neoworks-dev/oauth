package vault

import (
	"net/http"
	"net/url"

	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/scopes"
	"github.com/neoworks/oauth/internal/store"
)

// challengeView is what the consent screen needs to know about a pending
// authorization request.
type challengeView struct {
	ClientID   string   `json:"clientId"`
	ClientName string   `json:"clientName"`
	Scopes     []string `json:"scopes"`
	// FirstParty is true for Neoworks' own apps, the only ones that may skip the
	// consent screen.
	FirstParty bool `json:"firstParty"`
	// Description, Owner, Verified, ReviewStatus and LogoURL tell the user who
	// is behind the app. Owner is null for an app nobody owns, LogoURL when
	// there is no logo users may see; the screen then shows initials.
	Description  string       `json:"description"`
	Owner        *store.Owner `json:"owner"`
	Verified     bool         `json:"verified"`
	ReviewStatus string       `json:"reviewStatus"`
	LogoURL      *string      `json:"logoUrl"`
	// ScopeOwners names the owner of each scope (handle) the request touches.
	ScopeOwners    map[string]store.Owner `json:"scopeOwners"`
	RedirectOrigin string                 `json:"redirectOrigin"`
	Install        *installView           `json:"install"`
	// Collections are the registry schemas of the collections the request and
	// the app's earlier authorization name, for their titles and node descriptors.
	Collections map[string]store.CollectionSchema `json:"collections"`
	// History is what the signed-in user earlier authorized for this app; null
	// when the user never did or is not signed in.
	History *historyView `json:"history"`
}

type installView struct {
	ID      string `json:"id"`
	EncPub  string `json:"encPub"`
	SignPub string `json:"signPub"`
	Name    string `json:"name"`
}

func (server *Server) handleChallenge(response http.ResponseWriter, request *http.Request) {
	challenge, err := server.state.GetLoginChallenge(request.Context(), request.URL.Query().Get("login_challenge"))
	if err != nil {
		writeError(response, http.StatusNotFound, "challenge_not_found")
		return
	}
	client, err := server.store.GetClient(request.Context(), challenge.ClientID)
	if err != nil {
		writeError(response, http.StatusNotFound, "challenge_not_found")
		return
	}
	if client.Suspended() {
		writeError(response, http.StatusForbidden, "app_suspended")
		return
	}
	history, err := server.historyFor(request, client.ID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	collections, err := server.store.CollectionSchemas(request.Context(), challengeCollections(challenge.Scopes, history))
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	view := challengeView{
		ClientID:       client.ID,
		ClientName:     displayName(client.Name, client.ID),
		Scopes:         challenge.Scopes,
		FirstParty:     client.FirstParty,
		RedirectOrigin: originOf(challenge.RedirectURI),
		Install:        installViewOf(challenge.Install),
		Collections:    collections,
		History:        history,
	}
	if err := server.describeApp(request, &view, client, history); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, view)
}

// describeApp adds who is behind the app and who owns the scopes it asks for.
func (server *Server) describeApp(request *http.Request, view *challengeView, client *store.Client, history *historyView) error {
	owner, err := server.store.ClientOwner(request.Context(), client)
	if err != nil {
		return err
	}
	scopeOwners, err := server.store.HandleOwners(request.Context(), scopes.Handles(challengeCollections(view.Scopes, history)))
	if err != nil {
		return err
	}
	view.Description = client.Description
	view.Owner = owner
	view.Verified = client.Verified || client.FirstParty
	view.ReviewStatus = client.ReviewStatus
	view.ScopeOwners = scopeOwners
	if assetID := client.LogoAssetID(); assetID != "" {
		logoURL := server.config.AssetsURL + "/assets/" + assetID
		view.LogoURL = &logoURL
	}
	return nil
}

func displayName(name, fallback string) string {
	if name == "" {
		return fallback
	}
	return name
}

func installViewOf(install *cache.InstallRequest) *installView {
	if install == nil {
		return nil
	}
	return &installView{ID: install.ID, EncPub: install.EncPub, SignPub: install.SignPub, Name: install.Name}
}

// redirectWithCode builds the client redirect carrying the authorization code.
func redirectWithCode(redirectURI, code, state string) (string, error) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	values := target.Query()
	values.Set("code", code)
	if state != "" {
		values.Set("state", state)
	}
	target.RawQuery = values.Encode()
	return target.String(), nil
}

// handleDeny ends an authorization request the user refused, answering with the
// redirect that reports access_denied to the client.
func (server *Server) handleDeny(response http.ResponseWriter, request *http.Request) {
	var body struct {
		LoginChallenge string `json:"loginChallenge"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	challenge, err := server.state.TakeLoginChallenge(request.Context(), body.LoginChallenge)
	if err != nil {
		writeError(response, http.StatusNotFound, "challenge_not_found")
		return
	}
	target, err := url.Parse(challenge.RedirectURI)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	values := target.Query()
	values.Set("error", "access_denied")
	if challenge.State != "" {
		values.Set("state", challenge.State)
	}
	target.RawQuery = values.Encode()
	writeJSON(response, http.StatusOK, map[string]string{"redirect": target.String()})
}

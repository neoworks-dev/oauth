package vault

import (
	"net/http"
	"net/url"

	"github.com/neoworks/oauth/internal/cache"
)

// challengeView is what the consent screen needs to know about a pending
// authorization request.
type challengeView struct {
	ClientID       string       `json:"clientId"`
	ClientName     string       `json:"clientName"`
	Scopes         []string     `json:"scopes"`
	AutoGrant      bool         `json:"autoGrant"`
	RedirectOrigin string       `json:"redirectOrigin"`
	Install        *installView `json:"install"`
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
	view := challengeView{
		ClientID:       client.ID,
		ClientName:     displayName(client.Name, client.ID),
		Scopes:         challenge.Scopes,
		AutoGrant:      client.AutoGrantScopes,
		RedirectOrigin: originOf(challenge.RedirectURI),
		Install:        installViewOf(challenge.Install),
	}
	writeJSON(response, http.StatusOK, view)
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

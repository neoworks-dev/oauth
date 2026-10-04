package vault

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/tokens"
)

const authenticatorDeviceKind = "authenticator"

func authenticatorScopes() []string {
	return []string{"openid", "profile", "email"}
}

// AuthenticatorRouter mounts what the authenticator app calls on the oauth
// origin: prelogin and password login for a new device, and the handover
// delivery. The vault origin serves the browser's own login.
func (server *Server) AuthenticatorRouter(router chi.Router) {
	router.Post("/vault/prelogin", server.handlePrelogin)
	router.Post("/oauth/device-login", server.handleDeviceLogin)
	router.Post("/vault/handover/{sessionID}", server.handleHandoverDeliver)
}

// handleDeviceLogin signs an authenticator device in with the account password
// (the authKey after prelogin). It registers the device, returns the key bundle
// so the app can open the AMK once, and issues tokens for the authenticator's
// OAuth client, which is the only client allowed to deliver a handover.
func (server *Server) handleDeviceLogin(response http.ResponseWriter, request *http.Request) {
	body, user, ok := server.authenticatePassword(response, request)
	if !ok {
		return
	}
	ctx := request.Context()
	err := server.store.RegisterDevice(ctx, user.ID, body.DeviceID, cleanDeviceName(body.DeviceName), authenticatorDeviceKind)
	if err == store.ErrRevoked {
		writeError(response, http.StatusForbidden, "device_revoked")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	bundle, err := server.store.GetKeyBundle(ctx, user.ID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	issued, ok := server.issueAuthenticatorTokens(response, request, user.ID)
	if !ok {
		return
	}
	issued["userId"] = user.ID
	issued["email"] = user.Email
	issued["name"] = strings.TrimSpace(user.FirstName + " " + user.LastName)
	issued["bundle"] = bundle
	writeJSON(response, http.StatusOK, issued)
}

func (server *Server) issueAuthenticatorTokens(response http.ResponseWriter, request *http.Request, userID string) (map[string]any, bool) {
	clientID := server.config.AuthenticatorClientID
	accessToken, _, err := server.issuer.IssueAccessToken(tokens.AccessTokenParams{
		UserID: userID, ClientID: clientID, Scopes: authenticatorScopes(),
	})
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return nil, false
	}
	now := time.Now()
	refresh := store.RefreshToken{
		ID: uuid.NewString(), UserID: userID, ClientID: clientID, Scopes: authenticatorScopes(),
		ExpiresAt: now.Add(tokens.RefreshTokenTTL), CreatedAt: now,
	}
	if err := server.store.SaveRefreshToken(request.Context(), refresh); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return nil, false
	}
	return map[string]any{
		"access_token":  accessToken,
		"refresh_token": refresh.ID,
		"token_type":    "Bearer",
		"expires_in":    int(tokens.AccessTokenTTL.Seconds()),
		"scope":         strings.Join(authenticatorScopes(), " "),
	}, true
}

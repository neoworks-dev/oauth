package vault

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"time"

	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/scopes"
	"github.com/neoworks/oauth/internal/tokens"
	"github.com/neoworks/oauth/internal/wire"
)

type sessionContextKey struct{}

// authenticatedSession is the vault session of the current request.
type authenticatedSession struct {
	Token   string
	Session cache.VaultSession
}

func (server *Server) cookieName() string {
	if server.config.SecureCookies {
		return "__Host-nw_vault"
	}
	return "nw_vault"
}

func newSessionToken() string {
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	return wire.EncodeBase64URL(token)
}

func (server *Server) setSessionCookie(response http.ResponseWriter, token string) {
	http.SetCookie(response, &http.Cookie{
		Name:     server.cookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   int(cache.VaultSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   server.config.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

func (server *Server) clearSessionCookie(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{
		Name:     server.cookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   server.config.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// startSession creates a vault session for a user on a device and sets the cookie.
func (server *Server) startSession(response http.ResponseWriter, request *http.Request, userID, deviceID string) error {
	token := newSessionToken()
	session := cache.VaultSession{UserID: userID, DeviceID: deviceID, CreatedAt: time.Now().UTC()}
	if err := server.state.SaveVaultSession(request.Context(), token, session); err != nil {
		return err
	}
	server.setSessionCookie(response, token)
	return nil
}

// loadSession resolves the request's cookie to a live session on an active device.
func (server *Server) loadSession(request *http.Request) (*authenticatedSession, bool) {
	cookie, err := request.Cookie(server.cookieName())
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	session, err := server.state.GetVaultSession(request.Context(), cookie.Value)
	if err != nil {
		return nil, false
	}
	active, err := server.store.IsDeviceActive(request.Context(), session.UserID, session.DeviceID)
	if err != nil || !active {
		return nil, false
	}
	return &authenticatedSession{Token: cookie.Value, Session: *session}, true
}

func (server *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		current, ok := server.loadSession(request)
		if !ok {
			writeError(response, http.StatusUnauthorized, "unauthenticated")
			return
		}
		ctx := context.WithValue(request.Context(), sessionContextKey{}, current)
		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func sessionFrom(request *http.Request) *authenticatedSession {
	current, _ := request.Context().Value(sessionContextKey{}).(*authenticatedSession)
	return current
}

func (server *Server) handleSession(response http.ResponseWriter, request *http.Request) {
	current, ok := server.loadSession(request)
	if !ok {
		writeJSON(response, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	user, err := server.store.GetUserByID(request.Context(), current.Session.UserID)
	if err != nil {
		writeJSON(response, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"authenticated": true,
		"userId":        user.ID,
		"email":         user.Email,
		"name":          strings.TrimSpace(user.FirstName + " " + user.LastName),
		"deviceId":      current.Session.DeviceID,
		"escrowEnabled": user.EscrowEnabled,
	})
}

func (server *Server) handleLogout(response http.ResponseWriter, request *http.Request) {
	current, ok := server.loadSession(request)
	if ok {
		_ = server.state.DeleteVaultSession(request.Context(), current.Token)
	}
	server.clearSessionCookie(response)
	writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

func (server *Server) handleBundle(response http.ResponseWriter, request *http.Request) {
	bundle, err := server.store.GetKeyBundle(request.Context(), sessionFrom(request).Session.UserID)
	if err != nil {
		writeError(response, http.StatusNotFound, "no_bundle")
		return
	}
	writeJSON(response, http.StatusOK, bundle)
}

// handleToken mints a short-lived access token for the vault to call the API
// as the user principal. It carries no install, and reads and writes every
// collection the user has data in.
func (server *Server) handleToken(response http.ResponseWriter, request *http.Request) {
	userID := sessionFrom(request).Session.UserID
	collections, err := server.store.UserCollections(request.Context(), userID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	accessToken, _, err := server.issuer.IssueAccessToken(tokens.AccessTokenParams{
		UserID:   userID,
		ClientID: tokens.VaultClientID,
		Scopes:   append([]string{"openid", "profile", "email"}, scopes.ReadWrite(collections)...),
	})
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(tokens.AccessTokenTTL.Seconds()),
	})
}

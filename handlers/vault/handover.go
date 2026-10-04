package vault

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/ids"
	"github.com/neoworks/oauth/internal/tokens"
	"github.com/neoworks/oauth/internal/wire"
)

// sealedAMKBytes is the size of a 32 byte key sealed with crypto_box_seal.
const sealedAMKBytes = sealOverhead + nodeKeyBytes

func sessionBinding(sessionToken string) string {
	return wire.EncodeBase64URL(wire.Hash([]byte("handover-binding-v1:" + sessionToken)))
}

// handleHandoverCreate registers a handover session for the calling browser
// session. Only that session may read the result.
func (server *Server) handleHandoverCreate(response http.ResponseWriter, request *http.Request) {
	var body struct {
		SessionID string `json:"sessionId"`
	}
	if err := readJSON(request, &body); err != nil || !ids.IsLowercaseUUIDv4(body.SessionID) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	current := sessionFrom(request)
	created, err := server.state.CreateHandover(request.Context(), body.SessionID, cache.HandoverSession{
		BrowserSession: sessionBinding(current.Token),
		UserID:         current.Session.UserID,
	})
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if !created {
		writeError(response, http.StatusConflict, "session_exists")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"expiresIn": int(cache.HandoverTTL.Seconds())})
}

// handleHandoverPoll answers the creating browser session: pending until the
// authenticator delivers, then the sealed AMK exactly once.
func (server *Server) handleHandoverPoll(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	sessionID := chi.URLParam(request, "sessionID")
	handover, err := server.state.GetHandover(ctx, sessionID)
	current := sessionFrom(request)
	if err != nil || handover.BrowserSession != sessionBinding(current.Token) {
		writeError(response, http.StatusNotFound, "handover_not_found")
		return
	}
	if !handover.Delivered {
		writeJSON(response, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}
	delivered, err := server.state.TakeHandover(ctx, sessionID)
	if err != nil {
		writeError(response, http.StatusNotFound, "handover_not_found")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{
		"userId": delivered.UserID, "deviceId": delivered.DeviceID, "sealed": delivered.Sealed,
	})
}

// handleHandoverDeliver is called by the authenticator with its own access
// token. The token must come from the authenticator's OAuth client and proves
// whose authenticator it is; the handover session proves which browser asked.
func (server *Server) handleHandoverDeliver(response http.ResponseWriter, request *http.Request) {
	claims, ok := server.bearerClaims(request)
	if !ok || claims.ClientID != server.config.AuthenticatorClientID {
		writeError(response, http.StatusUnauthorized, "invalid_token")
		return
	}
	var body struct {
		UserID   string `json:"userId"`
		DeviceID string `json:"deviceId"`
		Sealed   string `json:"sealed"`
	}
	if err := readJSON(request, &body); err != nil || !validDelivery(body.DeviceID, body.Sealed) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if body.UserID != claims.Subject {
		writeError(response, http.StatusForbidden, "user_mismatch")
		return
	}
	server.storeDelivery(response, request, chi.URLParam(request, "sessionID"), body.UserID, body.DeviceID, body.Sealed)
}

func validDelivery(deviceID, sealed string) bool {
	if !ids.IsLowercaseUUIDv4(deviceID) {
		return false
	}
	_, err := decodeSized(sealed, sealedAMKBytes)
	return err == nil
}

func (server *Server) storeDelivery(response http.ResponseWriter, request *http.Request, sessionID, userID, deviceID, sealed string) {
	ctx := request.Context()
	handover, err := server.state.GetHandover(ctx, sessionID)
	if err != nil {
		writeError(response, http.StatusNotFound, "handover_not_found")
		return
	}
	if handover.UserID != userID {
		writeError(response, http.StatusForbidden, "user_mismatch")
		return
	}
	if handover.Delivered {
		writeError(response, http.StatusConflict, "already_delivered")
		return
	}
	handover.Delivered = true
	handover.DeviceID = deviceID
	handover.Sealed = sealed
	if err := server.state.DeliverHandover(ctx, sessionID, *handover); err != nil {
		writeError(response, http.StatusNotFound, "handover_not_found")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

// bearerClaims verifies the request's access token, including revocation.
func (server *Server) bearerClaims(request *http.Request) (*tokens.Claims, bool) {
	raw, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !found {
		return nil, false
	}
	claims, err := server.issuer.VerifyAccessToken(raw)
	if err != nil {
		return nil, false
	}
	revoked, err := server.state.IsRevoked(request.Context(), claims.ID)
	if err != nil || revoked {
		return nil, false
	}
	return claims, true
}

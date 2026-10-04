package vault

import (
	"net/http"

	"github.com/neoworks/oauth/internal/store"
)

// escrowChange tells a rotation what to do with the escrow wrap: replace it
// with a wrap of the new AMK, or drop it.
type escrowChange struct {
	SealedAmk string `json:"sealedAmk"`
	Disable   bool   `json:"disable"`
}

type rotateRequest struct {
	newPasswordMaterial
	CurrentAuthKey string        `json:"currentAuthKey"`
	Bundle         bundlePayload `json:"bundle"`
	Escrow         *escrowChange `json:"escrow"`
}

// handleRotate swaps the whole key bundle for the next version. Light rotations
// keep the identity keys; full rotations replace them.
func (server *Server) handleRotate(response http.ResponseWriter, request *http.Request) {
	var body rotateRequest
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	user, ok := server.reauthenticate(response, request, body.CurrentAuthKey)
	if !ok {
		return
	}
	rotation, err := buildRotation(user.ID, body)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if !server.replaceEscrowWrap(response, request, user, body.Escrow) {
		return
	}
	err = server.store.RotateBundle(request.Context(), rotation)
	if err == store.ErrConflict {
		writeError(response, http.StatusConflict, "bundle_version_conflict")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if !server.finishEscrowChange(response, request, user, body.Escrow) {
		return
	}
	writeJSON(response, http.StatusOK, map[string]uint32{"version": rotation.Bundle.Version})
}

// reauthenticate checks the current authKey of the session's user. It writes
// the HTTP error itself.
func (server *Server) reauthenticate(response http.ResponseWriter, request *http.Request, currentAuthKey string) (*store.User, bool) {
	userID := sessionFrom(request).Session.UserID
	if server.exceeded(request, "reauth:"+userID, loginMaxPerEmail, loginWindow) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return nil, false
	}
	user, err := server.store.GetUserByID(request.Context(), userID)
	authKey, validKey := parseAuthKey(currentAuthKey)
	if err != nil || !validKey || !verifyAuthKey(user, authKey) {
		writeError(response, http.StatusUnauthorized, "invalid_credentials")
		return nil, false
	}
	return user, true
}

func buildRotation(userID string, body rotateRequest) (store.Rotation, error) {
	if body.Bundle.Version != body.ExpectedVersion+1 {
		return store.Rotation{}, errInvalidPayload
	}
	if err := checkOpaqueBundleFields(body.Bundle); err != nil {
		return store.Rotation{}, err
	}
	if _, err := verifiedIdentity(userID, body.Bundle); err != nil {
		return store.Rotation{}, err
	}
	change, err := body.passwordChange(userID)
	if err != nil {
		return store.Rotation{}, err
	}
	if body.Bundle.AmkPassword != body.AmkPassword {
		return store.Rotation{}, errInvalidPayload
	}
	return store.Rotation{
		UserID:          userID,
		ExpectedVersion: body.ExpectedVersion,
		AuthHash:        change.AuthHash,
		Bundle:          storedBundle(userID, body.Bundle, body.Pwhash),
	}, nil
}

// replaceEscrowWrap registers the new AMK with escrow before the bundle swap,
// so escrow never lags behind a successful rotation.
func (server *Server) replaceEscrowWrap(response http.ResponseWriter, request *http.Request, user *store.User, change *escrowChange) bool {
	if !user.EscrowEnabled || (change != nil && change.Disable) {
		return true
	}
	if change == nil || change.SealedAmk == "" {
		writeError(response, http.StatusBadRequest, "escrow_wrap_required")
		return false
	}
	if _, err := decodeSized(change.SealedAmk, sealedAMKBytes); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	if err := server.escrow.Enroll(request.Context(), user.ID, change.SealedAmk); err != nil {
		writeError(response, http.StatusBadGateway, "escrow_failed")
		return false
	}
	return true
}

// finishEscrowChange removes the escrow record after a rotation that disables it.
func (server *Server) finishEscrowChange(response http.ResponseWriter, request *http.Request, user *store.User, change *escrowChange) bool {
	if change == nil || !change.Disable || !user.EscrowEnabled {
		return true
	}
	if err := server.escrow.Remove(request.Context(), user.ID); err != nil {
		writeError(response, http.StatusBadGateway, "escrow_failed")
		return false
	}
	if err := server.store.SetEscrowEnabled(request.Context(), user.ID, false); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return false
	}
	return true
}

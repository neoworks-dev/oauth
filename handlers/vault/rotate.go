package vault

import (
	"errors"
	"net/http"

	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/wire"
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

var errRotationInProgress = errors.New("a full rotation is still being completed")

// handleRotate swaps the whole key bundle for the next version. Light rotations
// keep the identity keys; full rotations replace them and keep the replaced
// identity in the bundle until /vault/rotate/complete.
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
	rotation, err := server.buildCheckedRotation(request, user.ID, body)
	if errors.Is(err, errRotationInProgress) {
		writeError(response, http.StatusConflict, "rotation_in_progress")
		return
	}
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

func (server *Server) buildCheckedRotation(request *http.Request, userID string, body rotateRequest) (store.Rotation, error) {
	rotation, err := buildRotation(userID, body)
	if err != nil {
		return store.Rotation{}, err
	}
	current, err := server.store.GetKeyBundle(request.Context(), userID)
	if err != nil {
		return store.Rotation{}, err
	}
	if err := checkPreviousIdentity(current, body.Bundle); err != nil {
		return store.Rotation{}, err
	}
	return rotation, nil
}

// checkPreviousIdentity enforces how the replaced identity travels. A rotation
// that changes the identity must carry the identity it replaces and may not
// start while another is unfinished. A rotation that keeps the identity carries
// the unfinished previous identity forward unchanged, or none.
func checkPreviousIdentity(current *store.KeyBundle, next bundlePayload) error {
	identityChanged := next.EncPub != current.EncPub || next.SignPub != current.SignPub
	if identityChanged && current.Previous != nil {
		return errRotationInProgress
	}
	if identityChanged {
		return requirePrevious(next.Previous, current.EncPub, current.SignPub)
	}
	if current.Previous != nil {
		return requirePrevious(next.Previous, current.Previous.EncPub, current.Previous.SignPub)
	}
	if next.Previous != nil {
		return errInvalidPayload
	}
	return nil
}

func requirePrevious(previous *previousIdentityPayload, encPub, signPub string) error {
	if previous == nil || previous.EncPub != encPub || previous.SignPub != signPub {
		return errInvalidPayload
	}
	_, err := decodeBounded(previous.IdentityPrivate, maxBlobTextSize)
	return err
}

type completeRotationRequest struct {
	CurrentAuthKey string `json:"currentAuthKey"`
	Version        uint32 `json:"version"`
	// RotationSig is the previous identity's signature over the new identity
	// at the next identity version.
	RotationSig string `json:"rotationSig"`
}

// handleRotateComplete drops the previous identity once the client has rewrapped
// every key to the new one, and appends the new identity to the key history.
// Completing a rotation that is already complete succeeds.
func (server *Server) handleRotateComplete(response http.ResponseWriter, request *http.Request) {
	var body completeRotationRequest
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	user, ok := server.reauthenticate(response, request, body.CurrentAuthKey)
	if !ok {
		return
	}
	bundle, err := server.store.GetKeyBundle(request.Context(), user.ID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if bundle.Version != body.Version {
		writeError(response, http.StatusConflict, "bundle_version_conflict")
		return
	}
	if bundle.Previous == nil {
		writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	link, err := verifiedIdentityLink(user.ID, bundle, body.RotationSig)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_rotation_sig")
		return
	}
	err = server.store.CompleteRotation(request.Context(), user.ID, body.Version, link)
	if err == store.ErrConflict {
		writeError(response, http.StatusConflict, "bundle_version_conflict")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

// verifiedIdentityLink checks that the replaced identity signed the bundle's
// identity as the next history version.
func verifiedIdentityLink(userID string, bundle *store.KeyBundle, rotationSig string) (store.IdentityLink, error) {
	previousSignPub, err := decodeSized(bundle.Previous.SignPub, publicKeyBytes)
	if err != nil {
		return store.IdentityLink{}, err
	}
	signPub, err := decodeSized(bundle.SignPub, publicKeyBytes)
	if err != nil {
		return store.IdentityLink{}, err
	}
	encPub, err := decodeSized(bundle.EncPub, publicKeyBytes)
	if err != nil {
		return store.IdentityLink{}, err
	}
	signature, err := decodeSized(rotationSig, signatureBytes)
	if err != nil {
		return store.IdentityLink{}, err
	}
	message := wire.IdentityRotationMessage(userID, bundle.IdentityVersion, signPub, encPub)
	if !wire.Verify(previousSignPub, message, signature) {
		return store.IdentityLink{}, errInvalidPayload
	}
	return store.IdentityLink{
		Version: bundle.IdentityVersion, SignPub: bundle.SignPub, EncPub: bundle.EncPub, RotationSig: rotationSig,
	}, nil
}

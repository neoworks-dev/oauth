package vault

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/internal/store"
)

const (
	escrowPublicWindow      = time.Hour
	escrowPublicMaxPerIP    = 30
	escrowRecoveryPathLimit = "escrow_public_ip:"
)

func (server *Server) registerEscrowRoutes(api chi.Router) {
	api.Get("/escrow/status", server.handleEscrowStatus)
	api.Post("/escrow/enable", server.handleEscrowEnable)
	api.Post("/escrow/recoveries/{attemptID}/cancel", server.handleEscrowCancelAsUser)
}

// registerPublicEscrowRoutes are used by someone who cannot sign in. They are
// gated by a fresh email verification, or by the secret in a cancel link.
func (server *Server) registerPublicEscrowRoutes(api chi.Router) {
	api.Post("/escrow/recovery/start", server.handleEscrowRecoveryStart)
	api.Post("/escrow/recovery/claim", server.handleEscrowRecoveryClaim)
	api.Post("/escrow/recovery/cancel", server.handleEscrowCancelWithToken)
}

func escrowFailure(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrEscrowUnavailable):
		writeError(response, http.StatusServiceUnavailable, "escrow_unavailable")
	case errors.Is(err, ErrEscrowRateLimited):
		writeError(response, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, ErrEscrowPending):
		writeError(response, http.StatusConflict, "attempt_pending")
	case errors.Is(err, ErrEscrowNotEnrolled):
		writeError(response, http.StatusNotFound, "not_enrolled")
	case errors.Is(err, ErrRecoveryNotReady):
		writeError(response, http.StatusTooEarly, "not_ready")
	case errors.Is(err, ErrRecoveryGone):
		writeError(response, http.StatusGone, "recovery_gone")
	case errors.Is(err, ErrRecoverySecret):
		writeError(response, http.StatusForbidden, "invalid_secret")
	default:
		writeError(response, http.StatusBadGateway, "escrow_failed")
	}
}

func (server *Server) handleEscrowStatus(response http.ResponseWriter, request *http.Request) {
	userID := sessionFrom(request).Session.UserID
	user, err := server.store.GetUserByID(request.Context(), userID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	recoveries := []RecoveryAttempt{}
	if server.escrow.Available() && user.EscrowEnabled {
		recoveries, err = server.escrow.PendingRecoveries(request.Context(), userID)
		if err != nil {
			escrowFailure(response, err)
			return
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"available": server.escrow.Available(), "enabled": user.EscrowEnabled, "recoveries": recoveries,
	})
}

// handleEscrowEnable adds the escrow wrap to an account that chose "only you"
// at signup. It needs the password, because it lets Neoworks help decrypt.
func (server *Server) handleEscrowEnable(response http.ResponseWriter, request *http.Request) {
	var body struct {
		CurrentAuthKey string `json:"currentAuthKey"`
		SealedAmk      string `json:"sealedAmk"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	user, ok := server.reauthenticate(response, request, body.CurrentAuthKey)
	if !ok {
		return
	}
	if _, err := decodeSized(body.SealedAmk, sealedAMKBytes); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := server.escrow.Enroll(request.Context(), user.ID, body.SealedAmk); err != nil {
		escrowFailure(response, err)
		return
	}
	if err := server.store.SetEscrowEnabled(request.Context(), user.ID, true); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"enabled": true})
}

func (server *Server) handleEscrowCancelAsUser(response http.ResponseWriter, request *http.Request) {
	userID := sessionFrom(request).Session.UserID
	err := server.escrow.CancelAsUser(request.Context(), userID, chi.URLParam(request, "attemptID"))
	if err != nil {
		escrowFailure(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"cancelled": true})
}

// resetIdentity resolves a reset token, from a fresh email verification, to
// the account it belongs to. It does not consume the token.
func (server *Server) resetIdentity(request *http.Request, resetToken string) (*store.User, string, bool) {
	email, err := server.state.PeekResetToken(request.Context(), resetToken)
	if err != nil {
		return nil, "", false
	}
	user := server.findUser(request, email)
	if user == nil || !user.EscrowEnabled {
		return nil, "", false
	}
	return user, email, true
}

func (server *Server) publicEscrowLimited(request *http.Request) bool {
	return server.exceeded(request, escrowRecoveryPathLimit+clientIP(request), escrowPublicMaxPerIP, escrowPublicWindow)
}

func (server *Server) handleEscrowRecoveryStart(response http.ResponseWriter, request *http.Request) {
	var body struct {
		ResetToken string `json:"resetToken"`
		TempPub    string `json:"tempPub"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if server.publicEscrowLimited(request) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if _, err := decodeSized(body.TempPub, publicKeyBytes); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	user, email, ok := server.resetIdentity(request, body.ResetToken)
	if !ok {
		writeError(response, http.StatusForbidden, "invalid_reset_token")
		return
	}
	started, err := server.escrow.StartRecovery(request.Context(), user.ID, email, body.TempPub)
	if err != nil {
		escrowFailure(response, err)
		return
	}
	writeJSON(response, http.StatusOK, started)
}

func (server *Server) handleEscrowRecoveryClaim(response http.ResponseWriter, request *http.Request) {
	var body struct {
		ResetToken  string `json:"resetToken"`
		AttemptID   string `json:"attemptId"`
		ClaimSecret string `json:"claimSecret"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if server.publicEscrowLimited(request) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	user, _, ok := server.resetIdentity(request, body.ResetToken)
	if !ok {
		writeError(response, http.StatusForbidden, "invalid_reset_token")
		return
	}
	sealed, err := server.escrow.Claim(request.Context(), user.ID, body.AttemptID, body.ClaimSecret)
	if err != nil {
		escrowFailure(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"sealed": sealed})
}

func (server *Server) handleEscrowCancelWithToken(response http.ResponseWriter, request *http.Request) {
	var body struct {
		AttemptID string `json:"attemptId"`
		Token     string `json:"token"`
	}
	if err := readJSON(request, &body); err != nil || body.Token == "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if server.publicEscrowLimited(request) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if err := server.escrow.CancelWithToken(request.Context(), body.AttemptID, body.Token); err != nil {
		escrowFailure(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"cancelled": true})
}

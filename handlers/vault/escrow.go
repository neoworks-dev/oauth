package vault

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ErrEscrowUnavailable is returned when no escrow service is configured.
var ErrEscrowUnavailable = errors.New("escrow is not available")

// RecoveryAttempt is a started escrow recovery.
type RecoveryAttempt struct {
	ID          string    `json:"id"`
	ReadyAt     time.Time `json:"readyAt"`
	ClaimSecret string    `json:"claimSecret,omitempty"`
	Status      string    `json:"status"`
}

// Escrow is the vault's view of the escrow service. The service never sees
// anything but sealed key material.
type Escrow interface {
	Available() bool
	Enroll(ctx context.Context, userID, sealedAMK string) error
	Remove(ctx context.Context, userID string) error
	StartRecovery(ctx context.Context, userID, email, tempPub string) (*RecoveryAttempt, error)
	PendingRecoveries(ctx context.Context, userID string) ([]RecoveryAttempt, error)
	CancelAsUser(ctx context.Context, userID, attemptID string) error
	CancelWithToken(ctx context.Context, attemptID, cancelToken string) error
	Claim(ctx context.Context, attemptID, claimSecret string) (string, error)
}

// NoEscrow is the Escrow used when the deployment has no escrow service.
type NoEscrow struct{}

func (NoEscrow) Available() bool { return false }
func (NoEscrow) Enroll(context.Context, string, string) error {
	return ErrEscrowUnavailable
}
func (NoEscrow) Remove(context.Context, string) error { return ErrEscrowUnavailable }
func (NoEscrow) StartRecovery(context.Context, string, string, string) (*RecoveryAttempt, error) {
	return nil, ErrEscrowUnavailable
}
func (NoEscrow) PendingRecoveries(context.Context, string) ([]RecoveryAttempt, error) {
	return nil, ErrEscrowUnavailable
}
func (NoEscrow) CancelAsUser(context.Context, string, string) error { return ErrEscrowUnavailable }
func (NoEscrow) CancelWithToken(context.Context, string, string) error {
	return ErrEscrowUnavailable
}
func (NoEscrow) Claim(context.Context, string, string) (string, error) {
	return "", ErrEscrowUnavailable
}

// enrollEscrow registers the sealed AMK of a new account with the escrow
// service when the signup chose it. It writes the HTTP error itself and
// reports whether signup may continue.
func (server *Server) enrollEscrow(response http.ResponseWriter, request *http.Request, body signupRequest) bool {
	if body.Escrow == nil {
		return true
	}
	if !server.escrow.Available() {
		writeError(response, http.StatusServiceUnavailable, "escrow_unavailable")
		return false
	}
	if _, err := decodeBounded(body.Escrow.SealedAmk, maxBlobTextSize); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	if err := server.escrow.Enroll(request.Context(), body.UserID, body.Escrow.SealedAmk); err != nil {
		writeError(response, http.StatusBadGateway, "escrow_failed")
		return false
	}
	return true
}

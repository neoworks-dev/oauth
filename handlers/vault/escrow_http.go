package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPEscrow talks to the escrow service. It only ever carries sealed values.
type HTTPEscrow struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewHTTPEscrow(baseURL, serviceToken string) *HTTPEscrow {
	return &HTTPEscrow{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   serviceToken,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (escrow *HTTPEscrow) Available() bool {
	return true
}

// call performs a request and decodes a JSON answer into destination when the
// status is a success. Other statuses map to the sentinel errors.
func (escrow *HTTPEscrow) call(ctx context.Context, method, path string, body, destination any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, escrow.baseURL+path, payload)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+escrow.token)
	request.Header.Set("Content-Type", "application/json")
	reply, err := escrow.client.Do(request)
	if err != nil {
		return err
	}
	defer reply.Body.Close()
	if reply.StatusCode == http.StatusOK {
		return decodeReply(reply.Body, destination)
	}
	return escrowStatusError(reply.StatusCode)
}

func decodeReply(body io.Reader, destination any) error {
	if destination == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(body, maxBodyBytes)).Decode(destination)
}

func escrowStatusError(status int) error {
	switch status {
	case http.StatusTooManyRequests:
		return ErrEscrowRateLimited
	case http.StatusConflict:
		return ErrEscrowPending
	case http.StatusNotFound:
		return ErrEscrowNotEnrolled
	case http.StatusTooEarly:
		return ErrRecoveryNotReady
	case http.StatusGone:
		return ErrRecoveryGone
	case http.StatusForbidden:
		return ErrRecoverySecret
	default:
		return ErrEscrowUnavailable
	}
}

func (escrow *HTTPEscrow) Enroll(ctx context.Context, userID, sealedAMK string) error {
	return escrow.call(ctx, http.MethodPut, "/v1/escrow/"+url.PathEscape(userID), map[string]string{"sealedAmk": sealedAMK}, nil)
}

func (escrow *HTTPEscrow) Remove(ctx context.Context, userID string) error {
	return escrow.call(ctx, http.MethodDelete, "/v1/escrow/"+url.PathEscape(userID), nil, nil)
}

func (escrow *HTTPEscrow) StartRecovery(ctx context.Context, userID, email, tempPub string) (*RecoveryAttempt, error) {
	var started RecoveryAttempt
	err := escrow.call(ctx, http.MethodPost, "/v1/recovery", map[string]string{"userId": userID, "email": email, "tempPub": tempPub}, &started)
	if err != nil {
		return nil, err
	}
	started.Status = "pending"
	return &started, nil
}

func (escrow *HTTPEscrow) PendingRecoveries(ctx context.Context, userID string) ([]RecoveryAttempt, error) {
	var listing struct {
		Recoveries []RecoveryAttempt `json:"recoveries"`
	}
	err := escrow.call(ctx, http.MethodGet, "/v1/users/"+url.PathEscape(userID)+"/recoveries", nil, &listing)
	return listing.Recoveries, err
}

func (escrow *HTTPEscrow) CancelAsUser(ctx context.Context, userID, attemptID string) error {
	return escrow.call(ctx, http.MethodPost, "/v1/recovery/"+url.PathEscape(attemptID)+"/cancel", map[string]string{"userId": userID}, nil)
}

func (escrow *HTTPEscrow) CancelWithToken(ctx context.Context, attemptID, cancelToken string) error {
	return escrow.call(ctx, http.MethodPost, "/v1/recovery/"+url.PathEscape(attemptID)+"/cancel", map[string]string{"token": cancelToken}, nil)
}

func (escrow *HTTPEscrow) Claim(ctx context.Context, userID, attemptID, claimSecret string) (string, error) {
	var released struct {
		SealedAmk string `json:"sealedAmk"`
	}
	err := escrow.call(ctx, http.MethodPost, "/v1/recovery/"+url.PathEscape(attemptID)+"/claim",
		map[string]string{"userId": userID, "claimSecret": claimSecret}, &released)
	return released.SealedAmk, err
}

package escrow

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

const maxRequestBytes = 16 << 10

// NewHandler serves the escrow API. Every route requires the shared service
// token; only the oauth service calls it.
func NewHandler(service *Service, serviceToken string) http.Handler {
	api := &api{service: service}
	router := chi.NewRouter()
	router.Use(requireServiceToken(serviceToken))
	router.Get("/v1/public-key", api.handlePublicKey)
	router.Put("/v1/escrow/{userID}", api.handleEnroll)
	router.Delete("/v1/escrow/{userID}", api.handleRemove)
	router.Get("/v1/escrow/{userID}", api.handleStatus)
	router.Get("/v1/users/{userID}/recoveries", api.handlePending)
	router.Post("/v1/recovery", api.handleStart)
	router.Post("/v1/recovery/{attemptID}/cancel", api.handleCancel)
	router.Post("/v1/recovery/{attemptID}/claim", api.handleClaim)
	return router
}

type api struct {
	service *Service
}

func requireServiceToken(expected string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			presented := request.Header.Get("Authorization")
			wanted := "Bearer " + expected
			if expected == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(wanted)) != 1 {
				writeError(response, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(response, request)
		})
	}
}

func readBody(request *http.Request, destination any) error {
	limited := http.MaxBytesReader(nil, request.Body, maxRequestBytes)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, destination)
}

func writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}

func decodeBytes(text string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(text)
	return decoded, err == nil
}

func (handler *api) handlePublicKey(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{
		"publicKey": base64.RawURLEncoding.EncodeToString(handler.service.PublicKey()),
	})
}

func (handler *api) handleEnroll(response http.ResponseWriter, request *http.Request) {
	var body struct {
		SealedAmk string `json:"sealedAmk"`
	}
	if err := readBody(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	sealed, decoded := decodeBytes(body.SealedAmk)
	if !decoded {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	err := handler.service.Enroll(request.Context(), chi.URLParam(request, "userID"), sealed)
	if errors.Is(err, ErrInvalidArgument) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"enrolled": true})
}

func (handler *api) handleRemove(response http.ResponseWriter, request *http.Request) {
	if err := handler.service.Remove(request.Context(), chi.URLParam(request, "userID")); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"enrolled": false})
}

func (handler *api) handleStatus(response http.ResponseWriter, request *http.Request) {
	enrolled, err := handler.service.IsEnrolled(request.Context(), chi.URLParam(request, "userID"))
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"enrolled": enrolled})
}

type attemptView struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	ReadyAt   time.Time `json:"readyAt"`
}

func (handler *api) handlePending(response http.ResponseWriter, request *http.Request) {
	pending, err := handler.service.Pending(request.Context(), chi.URLParam(request, "userID"))
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	views := make([]attemptView, 0, len(pending))
	for _, attempt := range pending {
		views = append(views, attemptView{ID: attempt.ID, Status: attempt.Status, CreatedAt: attempt.CreatedAt, ReadyAt: attempt.ReadyAt})
	}
	writeJSON(response, http.StatusOK, map[string]any{"recoveries": views})
}

func (handler *api) handleStart(response http.ResponseWriter, request *http.Request) {
	var body struct {
		UserID  string `json:"userId"`
		Email   string `json:"email"`
		TempPub string `json:"tempPub"`
	}
	if err := readBody(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	tempPub, decoded := decodeBytes(body.TempPub)
	if !decoded {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	started, err := handler.service.StartRecovery(request.Context(), body.UserID, body.Email, tempPub)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"id": started.ID, "readyAt": started.ReadyAt, "claimSecret": started.ClaimSecret,
	})
}

func (handler *api) handleCancel(response http.ResponseWriter, request *http.Request) {
	var body struct {
		UserID string `json:"userId"`
		Token  string `json:"token"`
	}
	if err := readBody(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	attemptID := chi.URLParam(request, "attemptID")
	var err error
	if body.Token != "" {
		err = handler.service.CancelWithToken(request.Context(), attemptID, body.Token)
	} else {
		err = handler.service.CancelAsUser(request.Context(), body.UserID, attemptID)
	}
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"cancelled": true})
}

func (handler *api) handleClaim(response http.ResponseWriter, request *http.Request) {
	var body struct {
		UserID      string `json:"userId"`
		ClaimSecret string `json:"claimSecret"`
	}
	if err := readBody(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	sealed, err := handler.service.Claim(request.Context(), body.UserID, chi.URLParam(request, "attemptID"), body.ClaimSecret)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"sealedAmk": base64.RawURLEncoding.EncodeToString(sealed)})
}

func writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidArgument):
		writeError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrNotEnrolled):
		writeError(response, http.StatusNotFound, "not_enrolled")
	case errors.Is(err, ErrRateLimited):
		writeError(response, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, ErrAttemptPending):
		writeError(response, http.StatusConflict, "attempt_pending")
	case errors.Is(err, ErrNotReady):
		writeError(response, http.StatusTooEarly, "not_ready")
	case errors.Is(err, ErrInvalidSecret):
		writeError(response, http.StatusForbidden, "invalid_secret")
	case errors.Is(err, ErrUnavailable):
		writeError(response, http.StatusGone, "unavailable")
	default:
		writeError(response, http.StatusInternalServerError, "server_error")
	}
}

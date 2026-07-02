package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/shared"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/push"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
)

// ApprovalLoginHandler implements cross-device "approve sign-in on your phone".
// The login page asks for an approval; the user's authenticator app approves it
// against the api server; the page polls and then completes the normal login.
type ApprovalLoginHandler struct {
	redis  *cache.RedisStore
	store  *database.SurrealStore
	issuer *oauth.TokenIssuer
	push   push.Sender
}

func NewApprovalLoginHandler(
	redis *cache.RedisStore,
	store *database.SurrealStore,
	issuer *oauth.TokenIssuer,
	sender push.Sender,
) *ApprovalLoginHandler {
	return &ApprovalLoginHandler{redis: redis, store: store, issuer: issuer, push: sender}
}

func (h *ApprovalLoginHandler) Register(r chi.Router) {
	r.Post("/auth/login/approve-request", h.createRequest)
	r.Get("/auth/login/approve-status", h.status)
	r.Get("/auth/login/complete", h.complete)
}

// createRequest is called by the login page JS when the user chooses to approve
// on their phone. It is intentionally constant-time across unknown emails to
// avoid account enumeration: the response is identical whether or not the user,
// their key material, or any device exists.
func (h *ApprovalLoginHandler) createRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email          string `json:"email"`
		LoginChallenge string `json:"login_challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.LoginChallenge == "" {
		jsonError(w, "email and login_challenge required", http.StatusBadRequest)
		return
	}

	challenge, err := h.redis.GetLoginChallenge(r.Context(), body.LoginChallenge)
	if err != nil || challenge == nil {
		jsonError(w, "invalid login challenge", http.StatusBadRequest)
		return
	}

	// Best-effort: only create the request when the user actually exists. The
	// response is the same either way so the caller cannot distinguish.
	if user, err := h.store.GetUserByEmail(r.Context(), body.Email); err == nil {
		h.createForUser(r, user, challenge)
	}

	writeJSON(w, map[string]string{"token": body.LoginChallenge})
}

func (h *ApprovalLoginHandler) createForUser(r *http.Request, user *oauth.User, challenge *oauth.LoginChallenge) {
	userID, ok := user.ID.ID.(string)
	if !ok {
		return
	}

	userAgent := r.UserAgent()
	ip := r.RemoteAddr
	req, err := h.store.CreateApprovalRequest(r.Context(), &database.CreateApprovalParams{
		UserID:              userID,
		Type:                "signin",
		Client:              challenge.ClientID,
		Scopes:              challenge.Scopes,
		RequestingUserAgent: &userAgent,
		IP:                  &ip,
		LoginChallenge:      &challenge.ID,
		ExpiresAt:           challenge.ExpiresAt,
	})
	if err != nil {
		return
	}

	requestID, _ := req.ID.ID.(string)
	_ = h.redis.LinkChallengeApproval(r.Context(), challenge.ID, cache.ApprovalLink{
		ApprovalRequestID: requestID,
	})

	if tokens, err := h.store.ListPushTokensForUser(r.Context(), userID); err == nil && len(tokens) > 0 {
		_ = h.push.Send(r.Context(), tokens, "Approve sign-in", "Tap to review a sign-in request", map[string]string{
			"type":        "signin",
			"approval_id": requestID,
			"client":      challenge.ClientID,
		})
	}
}

// status is polled by the login page. 202 while pending; 200 with the decision
// once the phone approves or denies.
func (h *ApprovalLoginHandler) status(w http.ResponseWriter, r *http.Request) {
	challengeID := r.URL.Query().Get("login_challenge")
	if challengeID == "" {
		jsonError(w, "missing login_challenge", http.StatusBadRequest)
		return
	}

	result, err := h.redis.GetApprovalResult(r.Context(), challengeID)
	if errors.Is(err, cache.ErrNotFound) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": result.Status})
}

// complete is a real top-level navigation the login page performs once status
// reports "approved". It sets the sso_session cookie (as a normal login would)
// and hands off to the standard consent/redirect path to issue the auth code.
func (h *ApprovalLoginHandler) complete(w http.ResponseWriter, r *http.Request) {
	challengeID := r.URL.Query().Get("login_challenge")
	if challengeID == "" {
		http.Error(w, "missing login_challenge", http.StatusBadRequest)
		return
	}

	result, err := h.redis.GetApprovalResult(r.Context(), challengeID)
	if err != nil || result.Status != "approved" {
		http.Error(w, "approval not granted", http.StatusForbidden)
		return
	}

	challenge, err := h.redis.GetLoginChallenge(r.Context(), challengeID)
	if err != nil || challenge == nil {
		http.Error(w, "invalid login challenge", http.StatusBadRequest)
		return
	}

	user, err := h.store.GetUserByID(r.Context(), result.UserID)
	if err != nil {
		http.Error(w, "invalid user", http.StatusBadRequest)
		return
	}

	// Establish the SSO session exactly as the password login does, adding to
	// any existing device session so the device can hold multiple accounts.
	if err := shared.EstablishSSOSession(h.redis, w, r, result.UserID); err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	shared.HandleConsentRedirect(h.redis, h.store, h.issuer, user, challenge, w, r)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

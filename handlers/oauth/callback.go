package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/shared"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type CallbackHandler struct {
	redis   *cache.RedisStore
	surreal *database.SurrealStore
	issuer  *oauth.TokenIssuer
}

func NewCallbackHandler(
	redis *cache.RedisStore,
	surreal *database.SurrealStore,
	issuer *oauth.TokenIssuer,
) *CallbackHandler {
	return &CallbackHandler{redis: redis, surreal: surreal, issuer: issuer}
}

func (h *CallbackHandler) Register(r chi.Router) {
	r.Post("/oauth/callback/login", h.handleLoginCallback)
	r.Post("/oauth/callback/consent", h.handleConsentCallback)
}

// ── Login callback ────────────────────────────────────────────────────────────
// Called by SvelteKit after the user submits their credentials.

type loginCallbackRequest struct {
	LoginChallenge string `json:"login_challenge"`
	UserID         string `json:"user_id"` // resolved by SvelteKit after validating credentials
}

func (h *CallbackHandler) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req loginCallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Fetch and delete the login challenge
	challenge, err := h.redis.GetLoginChallenge(ctx, req.LoginChallenge)
	if err != nil {
		http.Error(w, `{"error":"invalid_challenge"}`, http.StatusBadRequest)
		return
	}
	if time.Now().After(challenge.ExpiresAt) {
		http.Error(w, `{"error":"challenge_expired"}`, http.StatusBadRequest)
		return
	}
	_ = h.redis.DeleteLoginChallenge(ctx, req.LoginChallenge)

	// Check if user has already granted these scopes — skip consent if so
	grant, err := h.surreal.GetGrant(ctx, &models.RecordID{Table: "user", ID: req.UserID}, &models.RecordID{Table: "client", ID: challenge.ClientID})
	if err == nil && shared.ScopesAllowed(grant.Scopes, challenge.Scopes) {
		// All scopes already granted — skip consent, issue code directly
		code, err := h.issueCode(ctx, req.UserID, challenge)
		if err != nil {
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"redirect": redirectWithParams(challenge.RedirectURI, map[string]string{
				"code":  code,
				"state": challenge.State,
			}),
		})
		return
	}

	// New scopes — need consent
	consentChallenge := oauth.ConsentChallenge{
		ID:                  shared.GenerateID(),
		ClientID:            challenge.ClientID,
		UserID:              req.UserID,
		Scopes:              challenge.Scopes,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		RedirectURI:         challenge.RedirectURI,
		State:               challenge.State,
		CodeChallenge:       challenge.CodeChallenge,
		CodeChallengeMethod: challenge.CodeChallengeMethod,
	}
	if err := h.redis.SaveConsentChallenge(ctx, consentChallenge); err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	// Tell SvelteKit where to redirect the browser
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect": "/oauth/consent?consent_challenge=" + consentChallenge.ID,
	})
}

// ── Consent callback ──────────────────────────────────────────────────────────
// Called by SvelteKit after the user accepts or denies the consent screen.

type consentCallbackRequest struct {
	ConsentChallenge string   `json:"consent_challenge"`
	Accepted         bool     `json:"accepted"`
	Scopes           []string `json:"scopes"` // user may have deselected some
}

func (h *CallbackHandler) handleConsentCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req consentCallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	challenge, err := h.redis.GetConsentChallenge(ctx, req.ConsentChallenge)
	if err != nil {
		http.Error(w, `{"error":"invalid_challenge"}`, http.StatusBadRequest)
		return
	}
	if time.Now().After(challenge.ExpiresAt) {
		http.Error(w, `{"error":"challenge_expired"}`, http.StatusBadRequest)
		return
	}
	_ = h.redis.DeleteConsentChallenge(ctx, req.ConsentChallenge)

	if !req.Accepted {
		// User denied — redirect back to app with error, preserving state so the
		// client can match the response to its original request (CSRF defense).
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"redirect": redirectWithParams(challenge.RedirectURI, map[string]string{
				"error": "access_denied",
				"state": challenge.State,
			}),
		})
		return
	}

	// The consent screen can only narrow the requested scopes, never widen them.
	// req.Scopes is attacker-influenceable (it comes from the browser POST), so
	// clamp it to what the authorize request asked for — those were already
	// validated against the client's registration in handleAuthorize.
	grantedScopes := intersectScopes(challenge.Scopes, req.Scopes)

	// Persist grant so we can skip consent next time
	if err := h.surreal.UpsertGrant(ctx, &oauth.Grant{
		User:    &models.RecordID{Table: "user", ID: challenge.UserID},
		Client:  &models.RecordID{Table: "client", ID: challenge.ClientID},
		Scopes:  grantedScopes,
		Enabled: true,
	}); err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	// Build a temporary LoginChallenge-shaped struct to reuse issueCode
	pseudoChallenge := &oauth.LoginChallenge{
		ClientID:            challenge.ClientID,
		Scopes:              grantedScopes,
		RedirectURI:         challenge.RedirectURI,
		CodeChallenge:       challenge.CodeChallenge,
		CodeChallengeMethod: challenge.CodeChallengeMethod,
	}
	code, err := h.issueCode(ctx, challenge.UserID, pseudoChallenge)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect": redirectWithParams(challenge.RedirectURI, map[string]string{
			"code":  code,
			"state": challenge.State,
		}),
	})
}

// ── Shared ────────────────────────────────────────────────────────────────────

// redirectWithParams appends query parameters to a redirect URI, preserving any
// existing query and URL-encoding values. Empty values are skipped so an absent
// state never produces a dangling `state=`.
func redirectWithParams(redirectURI string, params map[string]string) string {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	query := parsed.Query()
	for key, value := range params {
		if value == "" {
			continue
		}
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// intersectScopes returns the requested scopes that are also present in allowed,
// preserving the order of allowed. Used to clamp a user's consent selection so
// it can only narrow the originally requested scopes, never widen them.
func intersectScopes(allowed, requested []string) []string {
	requestedSet := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		requestedSet[scope] = struct{}{}
	}
	result := make([]string, 0, len(allowed))
	for _, scope := range allowed {
		if _, ok := requestedSet[scope]; ok {
			result = append(result, scope)
		}
	}
	return result
}

func (h *CallbackHandler) issueCode(ctx context.Context, userID string, challenge *oauth.LoginChallenge) (string, error) {
	code := shared.GenerateID()
	ac := oauth.AuthCode{
		Code:                code,
		ClientID:            &models.RecordID{Table: "client", ID: challenge.ClientID},
		UserID:              &models.RecordID{Table: "user", ID: userID},
		RedirectURI:         challenge.RedirectURI,
		Scopes:              challenge.Scopes,
		CodeChallenge:       challenge.CodeChallenge,
		CodeChallengeMethod: challenge.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	if err := h.redis.SaveAuthCode(ctx, ac); err != nil {
		return "", err
	}
	return code, nil
}

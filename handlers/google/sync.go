package google

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// tokenSkew refreshes a little early, so a token handed to the Vault does not
// expire between this response and the Google call it is used for.
const tokenSkew = time.Minute

// maxEventLinkBatch bounds one SaveEventLinks transaction. The sync adapter
// chunks larger runs; without a cap a first full sync of a busy calendar would
// build a single statement thousands of clauses long.
const maxEventLinkBatch = 500

// ── Access token ──────────────────────────────────────────────────────────────

// accessToken vends a currently-valid Google access token to the Vault, which
// then calls googleapis.com directly. The refresh token never leaves this
// server, and the app never sees either — only the Vault does.
func (h *Handler) accessToken(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	token, expiresAt, err := h.freshAccessToken(r.Context(), user)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not_linked", http.StatusNotFound)
		return
	}
	if errors.Is(err, errLinkRevoked) {
		// 409, not 401: the caller's own neoworks token is fine. What is gone is
		// the Google grant, and the only fix is a fresh consent.
		jsonErr(w, "link_revoked", http.StatusConflict)
		return
	}
	if err != nil {
		slog.Error("mint google access token", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"expires_at":   expiresAt,
	})
}

// freshAccessToken returns the stored access token while it is still good, and
// refreshes otherwise. The refreshed token is written back so parallel devices
// reuse it instead of each spending a round-trip.
func (h *Handler) freshAccessToken(ctx context.Context, user models.RecordID) (string, time.Time, error) {
	account, err := h.google.Account(ctx, user)
	if err != nil {
		return "", time.Time{}, err
	}
	if stillValid(account) {
		return account.AccessToken, *account.ExpiresAt, nil
	}

	tokens, err := h.refreshAccess(ctx, account.RefreshToken)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := expiryOf(tokens)
	if err := h.google.SetAccessToken(ctx, user, tokens.AccessToken, expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return tokens.AccessToken, expiresAt, nil
}

func stillValid(account *database.GoogleAccount) bool {
	if account.AccessToken == "" || account.ExpiresAt == nil {
		return false
	}
	return time.Until(*account.ExpiresAt) > tokenSkew
}

func expiryOf(tokens *tokenResponse) time.Time {
	if tokens.ExpiresIn <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
}

func splitScopes(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return []string{}
	}
	return strings.Fields(scope)
}

// ── Calendar list ─────────────────────────────────────────────────────────────

// listCalendars proxies Google's calendarList so the app can render a picker
// without ever holding a Google token. The response passes through verbatim,
// including `accessRole` — the field that decides whether a calendar can sync
// both ways or only be pulled.
func (h *Handler) listCalendars(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	token, _, err := h.freshAccessToken(r.Context(), user)
	if errors.Is(err, database.ErrNotFound) {
		jsonErr(w, "not_linked", http.StatusNotFound)
		return
	}
	if errors.Is(err, errLinkRevoked) {
		jsonErr(w, "link_revoked", http.StatusConflict)
		return
	}
	if err != nil {
		slog.Error("google calendar list token", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}

	status, body, err := h.googleGet(r.Context(), "/calendar/v3/users/me/calendarList?maxResults=250", token)
	if err != nil {
		slog.Error("google calendar list", "error", err)
		jsonErr(w, "upstream_error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ── Calendar links ────────────────────────────────────────────────────────────

func (h *Handler) listCalendarLinks(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	links, err := h.google.CalendarLinks(r.Context(), user)
	if err != nil {
		slog.Error("list google calendar links", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links})
}

type calendarLinkBody struct {
	SpaceID          string `json:"space_id"`
	GoogleCalendarID string `json:"google_calendar_id"`
	AccessRole       string `json:"access_role"`
	// Absent leaves the stored cursor alone; an empty string clears it, which is
	// what a 410 from Google means — the next pull must be a full resync.
	SyncToken *string `json:"sync_token"`
	Enabled   *bool   `json:"enabled"`
}

// saveCalendarLink upserts one calendar → space mapping, and is also how the
// sync adapter advances (or clears) Google's pull cursor.
func (h *Handler) saveCalendarLink(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	var body calendarLinkBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid_body", http.StatusBadRequest)
		return
	}
	if body.SpaceID == "" || body.GoogleCalendarID == "" {
		jsonErr(w, "space_id and google_calendar_id required", http.StatusBadRequest)
		return
	}

	err := h.google.SaveCalendarLink(r.Context(), user, database.SaveGoogleCalendarLinkParams{
		SpaceID:          body.SpaceID,
		GoogleCalendarID: body.GoogleCalendarID,
		AccessRole:       accessRoleOf(body.AccessRole),
		SyncToken:        body.SyncToken,
		Enabled:          enabledOf(body.Enabled),
	})
	if err != nil {
		slog.Error("save google calendar link", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// accessRoleOf keeps the column inside the values the schema asserts. An
// unrecognized role degrades to reader — pull-only — rather than failing the
// write, because the safe default is not pushing to a calendar we may not own.
func accessRoleOf(role string) string {
	switch role {
	case "owner", "writer", "reader", "freeBusyReader":
		return role
	default:
		return "reader"
	}
}

func enabledOf(enabled *bool) bool {
	if enabled == nil {
		return true
	}
	return *enabled
}

func (h *Handler) deleteCalendarLink(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	calendarID := r.URL.Query().Get("google_calendar_id")
	if calendarID == "" {
		jsonErr(w, "google_calendar_id required", http.StatusBadRequest)
		return
	}
	if err := h.google.DeleteCalendarLink(r.Context(), user, calendarID); err != nil {
		slog.Error("delete google calendar link", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ── Event links ───────────────────────────────────────────────────────────────

// listEventLinks returns the uid → Google event map the sync adapter diffs its
// local rows against. `content_hash` is the guard that stops a second device
// re-pushing an event the first one already pushed.
func (h *Handler) listEventLinks(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	links, err := h.google.EventLinks(r.Context(), user, r.URL.Query().Get("google_calendar_id"))
	if err != nil {
		slog.Error("list google event links", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links})
}

func (h *Handler) saveEventLinks(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	var body struct {
		Links []database.GoogleEventLink `json:"links"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid_body", http.StatusBadRequest)
		return
	}
	if len(body.Links) > maxEventLinkBatch {
		jsonErr(w, "too_many_links", http.StatusBadRequest)
		return
	}
	if invalid := firstIncompleteLink(body.Links); invalid != "" {
		jsonErr(w, invalid, http.StatusBadRequest)
		return
	}

	if err := h.google.SaveEventLinks(r.Context(), user, body.Links); err != nil {
		slog.Error("save google event links", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": len(body.Links)})
}

// firstIncompleteLink names the missing field of the first unusable link, or ""
// when the batch is fine. A link without both ids is not a join.
func firstIncompleteLink(links []database.GoogleEventLink) string {
	for _, link := range links {
		if link.UID == "" {
			return "uid required"
		}
		if link.GoogleEventID == "" {
			return "google_event_id required"
		}
		if link.GoogleCalendarID == "" {
			return "google_calendar_id required"
		}
	}
	return ""
}

func (h *Handler) deleteEventLink(w http.ResponseWriter, r *http.Request) {
	user, ok := caller(w, r)
	if !ok {
		return
	}

	uid := r.URL.Query().Get("uid")
	if uid == "" {
		jsonErr(w, "uid required", http.StatusBadRequest)
		return
	}
	if err := h.google.DeleteEventLink(r.Context(), user, uid); err != nil {
		slog.Error("delete google event link", "error", err)
		jsonErr(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

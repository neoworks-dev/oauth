package handlers

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/database"
)

type UserInfoHandler struct {
	store  *database.SurrealStore
	issuer *oauth.TokenIssuer
}

func NewUserInfoHandler(store *database.SurrealStore, issuer *oauth.TokenIssuer) *UserInfoHandler {
	return &UserInfoHandler{
		store:  store,
		issuer: issuer,
	}
}

func (h *UserInfoHandler) Register(router chi.Router) {
	router.Get("/oauth/userinfo", h.handle)
}

func (h *UserInfoHandler) handle(w http.ResponseWriter, r *http.Request) {
	claim := middleware.ClaimFromContext(r.Context()) // injected by jwtMiddleware

	user, err := h.store.GetUserByID(r.Context(), claim.Subject)
	if err != nil {
		http.Error(w, "{'error': 'not_found'}", http.StatusNotFound)
		return
	}

	// sub must be the bare user id string, not the driver's RecordID struct, so it
	// matches claim.Subject everywhere else and survives JSON without leaking
	// {Table, ID}. claim.Subject is already that id.
	info := map[string]any{
		"sub": claim.Subject,
	}

	if slices.Contains(claim.Scope, "email") {
		info["email"] = user.Email
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

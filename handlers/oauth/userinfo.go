package oauth

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

type UserInfoHandler struct {
	store Store
}

func NewUserInfoHandler(userStore Store) *UserInfoHandler {
	return &UserInfoHandler{store: userStore}
}

func (handler *UserInfoHandler) Register(router chi.Router) {
	router.Get("/oauth/userinfo", handler.handleUserInfo)
}

func (handler *UserInfoHandler) handleUserInfo(response http.ResponseWriter, request *http.Request) {
	claims := ClaimsFromContext(request.Context())
	user, err := handler.store.GetUserByID(request.Context(), claims.Subject)
	if err != nil {
		tokenError(response, "not_found", http.StatusNotFound)
		return
	}
	info := map[string]any{"sub": claims.Subject}
	if claims.HasScope("email") {
		info["email"] = user.Email
	}
	if claims.HasScope("profile") {
		info["name"] = strings.TrimSpace(user.FirstName + " " + user.LastName)
	}
	writeJSON(response, http.StatusOK, info)
}

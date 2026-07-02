package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/crypto"
)

type JWKSHandler struct {
	keys *crypto.KeyManager
}

func NewJWKSHandler(keys *crypto.KeyManager) *JWKSHandler {
	return &JWKSHandler{keys: keys}
}

func (h *JWKSHandler) Register(r chi.Router) {
	r.Get("/.well-known/jwks.json", h.handleJWKS)
}

func (h *JWKSHandler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := h.keys.JWKSJson()
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}
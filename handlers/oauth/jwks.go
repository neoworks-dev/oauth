package oauth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// KeySetSource renders the public JWKS document.
type KeySetSource interface {
	JWKSJSON() ([]byte, error)
}

type JWKSHandler struct {
	keys KeySetSource
}

func NewJWKSHandler(keys KeySetSource) *JWKSHandler {
	return &JWKSHandler{keys: keys}
}

func (handler *JWKSHandler) Register(router chi.Router) {
	router.Get("/.well-known/jwks.json", handler.handleJWKS)
}

func (handler *JWKSHandler) handleJWKS(response http.ResponseWriter, request *http.Request) {
	document, err := handler.keys.JWKSJSON()
	if err != nil {
		http.Error(response, "server_error", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = response.Write(document)
}

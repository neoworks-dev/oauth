package oauth

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

type DiscoveryHandler struct {
	issuerURL string
}

func NewDiscoveryHandler(issuerURL string) *DiscoveryHandler {
	return &DiscoveryHandler{issuerURL: strings.TrimRight(issuerURL, "/")}
}

func (handler *DiscoveryHandler) Register(router chi.Router) {
	router.Get("/.well-known/openid-configuration", handler.handleDiscovery)
}

func (handler *DiscoveryHandler) handleDiscovery(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer":                                handler.issuerURL,
		"authorization_endpoint":                handler.issuerURL + "/oauth/authorize",
		"token_endpoint":                        handler.issuerURL + "/oauth/token",
		"introspection_endpoint":                handler.issuerURL + "/oauth/introspect",
		"revocation_endpoint":                   handler.issuerURL + "/oauth/revoke",
		"userinfo_endpoint":                     handler.issuerURL + "/oauth/userinfo",
		"jwks_uri":                              handler.issuerURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported": []string{
			"openid", "profile", "email",
			"calendar:read", "calendar:write", "contacts:read", "contacts:write",
			"photos:read", "photos:write", "files:read", "files:write",
		},
	})
}

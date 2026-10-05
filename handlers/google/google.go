// Package google is a stateless proxy for Google's OAuth token endpoint. It
// adds the client secret, which the browser must never hold, and keeps nothing:
// codes and tokens are forwarded and neither stored nor logged.
package google

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/handlers/oauth"
)

const (
	defaultTokenEndpoint = "https://oauth2.googleapis.com/token"
	maxBodyBytes         = 8 << 10
	upstreamTimeout      = 10 * time.Second
)

type Config struct {
	ClientID            string
	ClientSecret        string
	AllowedRedirectURIs []string
	TokenEndpoint       string
	AcceptedScopes      []string
}

func ConfigFromEnv() Config {
	allowed := []string{}
	uris := os.Getenv("GOOGLE_REDIRECT_URI") + "," + os.Getenv("GOOGLE_NATIVE_REDIRECT_URI")
	for _, uri := range strings.Split(uris, ",") {
		trimmed := strings.TrimSpace(uri)
		if trimmed != "" {
			allowed = append(allowed, trimmed)
		}
	}
	return Config{
		ClientID:            os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret:        os.Getenv("GOOGLE_CLIENT_SECRET"),
		AllowedRedirectURIs: allowed,
		TokenEndpoint:       defaultTokenEndpoint,
		AcceptedScopes:      []string{"calendar:read", "calendar:write"},
	}
}

// Doer is the HTTP client used to reach Google.
type Doer interface {
	Do(request *http.Request) (*http.Response, error)
}

type Handler struct {
	config Config
	client Doer
}

func NewHandler(config Config, client Doer) *Handler {
	return &Handler{config: config, client: client}
}

// nativeAppRedirect is where the relay hands Google's answer to the native
// calendar app. Google only allows https redirects for a web client, so the
// consent page returns to the relay, which forwards code and state unchanged.
const nativeAppRedirect = "neoworks-calendar://google"

// handleNativeCallback relays Google's redirect to the native app's private scheme.
func (handler *Handler) handleNativeCallback(response http.ResponseWriter, request *http.Request) {
	forwarded := url.Values{}
	for _, name := range []string{"code", "state", "error"} {
		if value := request.URL.Query().Get(name); value != "" {
			forwarded.Set(name, value)
		}
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(response, request, nativeAppRedirect+"?"+forwarded.Encode(), http.StatusFound)
}

// Register mounts the proxy behind the given bearer authentication.
func (handler *Handler) Register(router chi.Router, authenticate func(http.Handler) http.Handler) {
	router.Get("/google/native-callback", handler.handleNativeCallback)
	router.Group(func(protected chi.Router) {
		protected.Use(authenticate)
		protected.Post("/google/token/exchange", handler.handleExchange)
		protected.Post("/google/token/refresh", handler.handleRefresh)
	})
}

func (handler *Handler) handleExchange(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirectUri"`
	}
	if !handler.readRequest(response, request, &body) {
		return
	}
	if body.Code == "" || !slices.Contains(handler.config.AllowedRedirectURIs, body.RedirectURI) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	handler.forward(response, request, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {body.Code},
		"redirect_uri": {body.RedirectURI},
	})
}

func (handler *Handler) handleRefresh(response http.ResponseWriter, request *http.Request) {
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if !handler.readRequest(response, request, &body) {
		return
	}
	if body.RefreshToken == "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	handler.forward(response, request, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {body.RefreshToken},
	})
}

// readRequest checks that the proxy is configured and the caller may use it,
// then decodes the JSON body.
func (handler *Handler) readRequest(response http.ResponseWriter, request *http.Request, destination any) bool {
	if handler.config.ClientID == "" || handler.config.ClientSecret == "" {
		writeError(response, http.StatusServiceUnavailable, "not_configured")
		return false
	}
	claims := oauth.ClaimsFromContext(request.Context())
	if claims == nil || !hasAnyScope(claims.Scope, handler.config.AcceptedScopes) {
		writeError(response, http.StatusForbidden, "insufficient_scope")
		return false
	}
	limited := http.MaxBytesReader(response, request.Body, maxBodyBytes)
	if err := json.NewDecoder(limited).Decode(destination); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func hasAnyScope(granted, accepted []string) bool {
	for _, scope := range accepted {
		if slices.Contains(granted, scope) {
			return true
		}
	}
	return false
}

// forward posts the grant to Google with the client credentials added and
// relays the token fields of the answer.
func (handler *Handler) forward(response http.ResponseWriter, request *http.Request, form url.Values) {
	form.Set("client_id", handler.config.ClientID)
	form.Set("client_secret", handler.config.ClientSecret)
	status, answer, err := handler.postToGoogle(request.Context(), form)
	if err != nil {
		writeError(response, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(answer)
}

func (handler *Handler) postToGoogle(ctx context.Context, form url.Values) (int, map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, handler.config.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	upstream.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reply, err := handler.client.Do(upstream)
	if err != nil {
		return 0, nil, err
	}
	defer reply.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(reply.Body, maxBodyBytes))
	if err != nil {
		return 0, nil, err
	}
	relayed, ok := relayFields(payload)
	if !ok {
		return http.StatusBadGateway, map[string]any{"error": "upstream_invalid_response"}, nil
	}
	return relayStatus(reply.StatusCode), relayed, nil
}

// relayStatus passes success and client errors through and reports upstream
// server errors as a bad gateway.
func relayStatus(status int) int {
	if status >= 500 {
		return http.StatusBadGateway
	}
	return status
}

var relayedFields = []string{"access_token", "refresh_token", "expires_in", "scope", "token_type", "error", "error_description"}

// relayFields keeps only the token fields of Google's answer.
func relayFields(payload []byte) (map[string]any, bool) {
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, false
	}
	relayed := map[string]any{}
	for _, field := range relayedFields {
		value, present := parsed[field]
		if present {
			relayed[field] = value
		}
	}
	return relayed, true
}

func writeError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": code})
}

package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// errLinkRevoked means Google no longer honours the stored refresh token — the
// user removed the app, changed their password, or the grant expired. It is not
// retryable: the only fix is a fresh consent.
var errLinkRevoked = errors.New("google link revoked")

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

type tokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// exchangeCode turns the authorization code into tokens. access_type=offline
// plus prompt=consent on the authorize request means this response carries a
// refresh token every time, including on a re-link.
func (h *Handler) exchangeCode(ctx context.Context, code string) (*tokenResponse, error) {
	return h.postToken(ctx, url.Values{
		"code":          {code},
		"client_id":     {h.config.ClientID},
		"client_secret": {h.config.ClientSecret},
		"redirect_uri":  {h.config.RedirectURI},
		"grant_type":    {"authorization_code"},
	})
}

// refreshAccess mints a new access token from the stored refresh token.
func (h *Handler) refreshAccess(ctx context.Context, refreshToken string) (*tokenResponse, error) {
	return h.postToken(ctx, url.Values{
		"refresh_token": {refreshToken},
		"client_id":     {h.config.ClientID},
		"client_secret": {h.config.ClientSecret},
		"grant_type":    {"refresh_token"},
	})
}

func (h *Handler) postToken(ctx context.Context, form url.Values) (*tokenResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.config.tokenURL(),
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := h.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, tokenFailure(body)
	}

	var tokens tokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &tokens, nil
}

func tokenFailure(body []byte) error {
	var failure tokenError
	if err := json.Unmarshal(body, &failure); err != nil {
		return fmt.Errorf("google token endpoint: %s", strings.TrimSpace(string(body)))
	}
	if failure.Error == "invalid_grant" {
		return errLinkRevoked
	}
	return fmt.Errorf("google token endpoint: %s", failure.Error)
}

// revokeAtGoogle invalidates the grant on Google's side. Best effort: a failure
// here must not block dropping the local rows, or a user who revoked at Google
// first could never unlink here.
func (h *Handler) revokeAtGoogle(ctx context.Context, token string) error {
	form := url.Values{"token": {token}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.config.revokeURL(),
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := h.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("google revoke returned %d", response.StatusCode)
	}
	return nil
}

// googleGet proxies one authenticated GET to the Calendar API and returns its
// status and body verbatim, so a Google error reaches the client unmangled.
func (h *Handler) googleGet(ctx context.Context, path, accessToken string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.config.apiBase()+path, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := h.http.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, body, nil
}

// identity is the Google account behind a grant.
type identity struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

// identityFromIDToken reads `sub` and `email` out of the id_token's payload
// without verifying its signature. That is safe here and only here: the token
// came back over TLS from Google's own token endpoint in response to a request
// carrying our client_secret, so there is no untrusted party in the path. An
// id_token received any other way must be verified.
func identityFromIDToken(idToken string) identity {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return identity{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return identity{}
	}
	var parsed identity
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return identity{}
	}
	return parsed
}

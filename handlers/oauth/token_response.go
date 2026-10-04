package oauth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/tokens"
)

// tokenResponse is the JSON body of a successful token request.
type tokenResponse struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	ExpiresIn    int            `json:"expires_in"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	Scope        string         `json:"scope"`
	Grant        *neoworksGrant `json:"neoworks_grant,omitempty"`
}

// neoworksGrant is what an install needs to decrypt its slice of the account.
type neoworksGrant struct {
	InstallID            string         `json:"installId"`
	Certificate          string         `json:"certificate"`
	CertificateSignature string         `json:"certificateSignature"`
	Grants               []grantPayload `json:"grants"`
}

type grantPayload struct {
	NodeID        string   `json:"nodeId"`
	PrincipalType string   `json:"principalType"`
	PrincipalID   string   `json:"principalId"`
	Role          string   `json:"role"`
	Facets        []uint32 `json:"facets"`
	Epoch         uint32   `json:"epoch"`
	WrappedKeys   string   `json:"wrappedKeys"`
	GrantedByType string   `json:"grantedByType"`
	GrantedByID   string   `json:"grantedById"`
	CertID        *string  `json:"certId"`
	Signature     string   `json:"signature"`
	CreatedAt     string   `json:"createdAt"`
	RevokedAt     *string  `json:"revokedAt"`
}

func newTokenResponse(accessToken, refreshToken string, tokenScopes []string) tokenResponse {
	return tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(tokens.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        strings.Join(tokenScopes, " "),
	}
}

func newNeoworksGrant(installID string, bundle *store.InstallGrantBundle) *neoworksGrant {
	payloads := make([]grantPayload, 0, len(bundle.Grants))
	for _, grant := range bundle.Grants {
		payloads = append(payloads, newGrantPayload(grant))
	}
	return &neoworksGrant{
		InstallID:            installID,
		Certificate:          bundle.Certificate.Bytes,
		CertificateSignature: bundle.Certificate.Signature,
		Grants:               payloads,
	}
}

func newGrantPayload(grant store.AccessGrant) grantPayload {
	payload := grantPayload{
		NodeID:        grant.NodeID,
		PrincipalType: grant.PrincipalType,
		PrincipalID:   grant.PrincipalID,
		Role:          grant.Role,
		Facets:        grant.Facets,
		Epoch:         grant.Epoch,
		WrappedKeys:   grant.WrappedKeys,
		GrantedByType: grant.GrantedByType,
		GrantedByID:   grant.GrantedByID,
		Signature:     grant.Signature,
		CreatedAt:     grant.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if grant.CertID != "" {
		certID := grant.CertID
		payload.CertID = &certID
	}
	if grant.RevokedAt != nil {
		revokedAt := grant.RevokedAt.UTC().Format("2006-01-02T15:04:05Z")
		payload.RevokedAt = &revokedAt
	}
	return payload
}

func writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}

func tokenError(response http.ResponseWriter, code string, status int) {
	writeJSON(response, status, map[string]string{"error": code})
}

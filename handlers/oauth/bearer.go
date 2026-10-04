package oauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/neoworks/oauth/internal/tokens"
)

// RevocationList answers whether an access token was revoked.
type RevocationList interface {
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

type claimsKey struct{}

// RequireBearer authenticates requests with an access token that is signed,
// unexpired and not revoked.
func RequireBearer(issuer *tokens.Issuer, revocations RevocationList) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			claims, status := verifyBearer(request, issuer, revocations)
			if status != http.StatusOK {
				tokenError(response, "invalid_token", status)
				return
			}
			ctx := context.WithValue(request.Context(), claimsKey{}, claims)
			next.ServeHTTP(response, request.WithContext(ctx))
		})
	}
}

func verifyBearer(request *http.Request, issuer *tokens.Issuer, revocations RevocationList) (*tokens.Claims, int) {
	header := request.Header.Get("Authorization")
	raw, found := strings.CutPrefix(header, "Bearer ")
	if !found || raw == "" {
		return nil, http.StatusUnauthorized
	}
	claims, err := issuer.VerifyAccessToken(raw)
	if err != nil {
		return nil, http.StatusUnauthorized
	}
	revoked, err := revocations.IsRevoked(request.Context(), claims.ID)
	if err != nil {
		return nil, http.StatusInternalServerError
	}
	if revoked {
		return nil, http.StatusUnauthorized
	}
	return claims, http.StatusOK
}

// ClaimsFromContext returns the claims RequireBearer verified.
func ClaimsFromContext(ctx context.Context) *tokens.Claims {
	claims, _ := ctx.Value(claimsKey{}).(*tokens.Claims)
	return claims
}

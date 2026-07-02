package sso

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	authmiddleware "github.com/neoworks/auth/middleware"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
)

// ResolveClaims reads the sso_session cookie and resolves it to the
// oauth.Claims shape that handlers/keys.Handler expects, so the keys API
// can be reused on the oauth origin without a JWT.
func ResolveClaims(redis *cache.RedisStore, r *http.Request) (*oauth.Claims, error) {
	cookie, err := r.Cookie("sso_session")
	if err != nil {
		return nil, err
	}

	userID, err := redis.GetSSOSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}

	return &oauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: userID},
	}, nil
}

// RequireSession authenticates requests via the sso_session cookie and
// injects oauth.Claims into the request context, allowing
// handlers/keys.Handler's authenticated routes to be reused unmodified.
func RequireSession(redis *cache.RedisStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := ResolveClaims(redis, r)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}

			ctx := authmiddleware.NewContextWithClaim(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

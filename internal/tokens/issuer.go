package tokens

import (
	"crypto/ecdsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Issuer struct {
	privateKey *ecdsa.PrivateKey
	issuerURL  string
}

func NewIssuer(privateKey *ecdsa.PrivateKey, issuerURL string) *Issuer {
	return &Issuer{privateKey: privateKey, issuerURL: issuerURL}
}

type AccessTokenParams struct {
	UserID    string
	ClientID  string
	Scopes    []string
	InstallID string
}

// IssueAccessToken signs a 15 minute token. An empty UserID produces a token
// without a subject.
func (issuer *Issuer) IssueAccessToken(params AccessTokenParams) (string, *Claims, error) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   params.UserID,
			Issuer:    issuer.issuerURL,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
		},
		ClientID:  params.ClientID,
		Scope:     params.Scopes,
		InstallID: params.InstallID,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(issuer.privateKey)
	if err != nil {
		return "", nil, err
	}
	return signed, claims, nil
}

// VerifyAccessToken checks signature and expiry. Revocation is the caller's
// concern.
func (issuer *Issuer) VerifyAccessToken(raw string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(raw, &Claims{}, func(parsed *jwt.Token) (any, error) {
		if parsed.Method != jwt.SigningMethodES256 {
			return nil, ErrTokenInvalid
		}
		return &issuer.privateKey.PublicKey, nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, ErrTokenExpired
	}
	if err != nil {
		return nil, ErrTokenInvalid
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}

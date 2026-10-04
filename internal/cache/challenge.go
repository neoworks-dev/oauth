package cache

import (
	"context"
	"time"
)

// InstallRequest carries the install parameters of an authorization request.
type InstallRequest struct {
	ID      string `json:"id"`
	EncPub  string `json:"enc_pub"`
	SignPub string `json:"sign_pub"`
	Name    string `json:"name"`
}

// LoginChallenge is the validated authorization request waiting for the user to
// sign in and consent in the account vault.
type LoginChallenge struct {
	ID                  string          `json:"id"`
	ClientID            string          `json:"client_id"`
	Scopes              []string        `json:"scopes"`
	RedirectURI         string          `json:"redirect_uri"`
	State               string          `json:"state"`
	CodeChallenge       string          `json:"code_challenge"`
	CodeChallengeMethod string          `json:"code_challenge_method"`
	Install             *InstallRequest `json:"install,omitempty"`
	ExpiresAt           time.Time       `json:"expires_at"`
}

func (store *Store) SaveLoginChallenge(ctx context.Context, challenge LoginChallenge) error {
	return store.saveJSON(ctx, "login_challenge:"+challenge.ID, challenge, time.Until(challenge.ExpiresAt))
}

func (store *Store) GetLoginChallenge(ctx context.Context, challengeID string) (*LoginChallenge, error) {
	var challenge LoginChallenge
	err := store.getJSON(ctx, "login_challenge:"+challengeID, &challenge)
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

// TakeLoginChallenge reads and deletes the challenge so it can be used once.
func (store *Store) TakeLoginChallenge(ctx context.Context, challengeID string) (*LoginChallenge, error) {
	var challenge LoginChallenge
	err := store.takeJSON(ctx, "login_challenge:"+challengeID, &challenge)
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

// AuthCode is a one-use authorization code.
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	InstallID           string    `json:"install_id,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func (store *Store) SaveAuthCode(ctx context.Context, code AuthCode) error {
	return store.saveJSON(ctx, "code:"+code.Code, code, time.Until(code.ExpiresAt))
}

func (store *Store) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	var authCode AuthCode
	err := store.takeJSON(ctx, "code:"+code, &authCode)
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}

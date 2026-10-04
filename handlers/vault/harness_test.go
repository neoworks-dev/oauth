package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/neoworks/oauth/internal/mail"
	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/tokens"
)

var testSurreal *testsupport.Surreal

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	surreal, err := testsupport.StartSurreal()
	if err != nil {
		panic(err)
	}
	testSurreal = surreal
	code := m.Run()
	if surreal != nil {
		surreal.Stop()
	}
	os.Exit(code)
}

// testVault is a vault server over real Surreal and in-process Redis.
type testVault struct {
	server  *Server
	browser *testsupport.Browser
	redis   *miniredis.Miniredis
}

func newTestVault(t *testing.T) *testVault {
	t.Helper()
	return newTestVaultWithEscrow(t, NoEscrow{})
}

func newTestVaultWithEscrow(t *testing.T, escrow Escrow) *testVault {
	t.Helper()
	if testSurreal == nil {
		t.Skip("surreal binary not available")
	}
	redisServer, redis := testsupport.NewRedis(t)
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	server := NewServer(Config{
		VaultURL: "http://vault.test", APIURL: "http://api.test", OAuthURL: "http://oauth.test",
		Debug: true, SecureCookies: false, PreloginSecret: []byte("test-secret"), AuthenticatorClientID: "neoworks-authenticator",
	}, testSurreal.Store, redis, tokens.NewIssuer(signingKey, "http://oauth.test"), mail.NewSender(mail.Config{}), escrow)
	return &testVault{server: server, browser: testsupport.NewBrowser(t, server.Router()), redis: redisServer}
}

// accessToken issues an authenticator token for a user the way the token
// endpoint would.
func (vault *testVault) accessToken(userID, installID string) string {
	return vault.accessTokenFor(userID, "neoworks-authenticator", installID)
}

func (vault *testVault) accessTokenFor(userID, clientID, installID string) string {
	signed, _, err := vault.server.issuer.IssueAccessToken(tokens.AccessTokenParams{
		UserID: userID, ClientID: clientID, Scopes: []string{"openid"}, InstallID: installID,
	})
	if err != nil {
		panic(err)
	}
	return signed
}

// signIn logs an existing account in on a fresh browser.
func (vault *testVault) signIn(t *testing.T, account *testsupport.Account) *testsupport.Browser {
	t.Helper()
	other := testsupport.NewBrowser(t, vault.server.Router())
	response := other.Do("POST", "/vault/login", map[string]any{
		"email": account.Email, "authKey": account.AuthKeyText(), "deviceId": account.DeviceID, "deviceName": "Test",
	}, nil)
	if response.Status != 200 {
		t.Fatalf("login: %d %s", response.Status, response.Raw)
	}
	return other
}

// verifyEmail completes the emailed-code step for an address.
func (vault *testVault) verifyEmail(t *testing.T, email string) {
	t.Helper()
	sent := vault.browser.Do("POST", "/vault/signup/send-code", map[string]any{"email": email}, nil)
	if sent.Status != 200 {
		t.Fatalf("send-code: %d %s", sent.Status, sent.Raw)
	}
	verified := vault.browser.Do("POST", "/vault/signup/verify-code", map[string]any{"email": email, "code": sent.Body["code"]}, nil)
	if verified.Status != 200 {
		t.Fatalf("verify-code: %d %s", verified.Status, verified.Raw)
	}
}

// signUp registers an account through the real endpoints.
func (vault *testVault) signUp(t *testing.T, account *testsupport.Account) {
	t.Helper()
	vault.verifyEmail(t, account.Email)
	created := vault.browser.Do("POST", "/vault/signup", account.SignupRequest(), nil)
	if created.Status != 200 {
		t.Fatalf("signup: %d %s", created.Status, created.Raw)
	}
}

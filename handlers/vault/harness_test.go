package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"

	"github.com/neoworks/oauth/internal/mail"
	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/tokens"
)

var testSurreal *testsupport.Surreal

func TestMain(m *testing.M) {
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
}

func newTestVault(t *testing.T) *testVault {
	t.Helper()
	if testSurreal == nil {
		t.Skip("surreal binary not available")
	}
	_, redis := testsupport.NewRedis(t)
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	server := NewServer(Config{
		VaultURL: "http://vault.test", APIURL: "http://api.test", OAuthURL: "http://oauth.test",
		Debug: true, SecureCookies: false, PreloginSecret: []byte("test-secret"),
	}, testSurreal.Store, redis, tokens.NewIssuer(signingKey, "http://oauth.test"), mail.NewSender(mail.Config{}), NoEscrow{})
	return &testVault{server: server, browser: testsupport.NewBrowser(t, server.Router())}
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

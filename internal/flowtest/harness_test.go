package flowtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	googlehandler "github.com/neoworks/oauth/handlers/google"
	vaulthandler "github.com/neoworks/oauth/handlers/vault"
	"github.com/neoworks/oauth/internal/app"
	"github.com/neoworks/oauth/internal/mail"
	"github.com/neoworks/oauth/internal/signing"
	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/tokens"
	"github.com/surrealdb/surrealdb.go/pkg/models"
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

const (
	vaultOrigin = "http://vault.test"
	appRedirect = "http://app.test/callback"
)

// system is the full service over real Surreal and in-process Redis.
type system struct {
	t        *testing.T
	redis    *miniredis.Miniredis
	oauth    http.Handler
	vault    http.Handler
	browser  *testsupport.Browser
	clientID string
}

func newSystem(t *testing.T) *system {
	t.Helper()
	if testSurreal == nil {
		t.Skip("surreal binary not available")
	}
	redisServer, redis := testsupport.NewRedis(t)
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuer := tokens.NewIssuer(signingKey, "http://oauth.test")
	vaultServer := vaulthandler.NewServer(vaulthandler.Config{
		VaultURL: vaultOrigin, APIURL: "http://api.test", OAuthURL: "http://oauth.test",
		Debug: true, PreloginSecret: []byte("secret"),
	}, testSurreal.Store, redis, issuer, mail.NewSender(mail.Config{}), vaulthandler.NoEscrow{})
	clientID := "app-" + testsupport.NewAccount("x@example.com").UserID[:8]
	if err := testSurreal.CreateClient(clientID, []string{appRedirect}, allScopes(), false); err != nil {
		t.Fatal(err)
	}
	oauthRouter := app.NewOAuthRouter(app.OAuthDependencies{
		Store: testSurreal.Store, State: redis, Issuer: issuer, Keys: signing.NewKeyManagerFromKey(signingKey),
		Vault: vaultServer, IssuerURL: "http://oauth.test", VaultURL: vaultOrigin,
		GoogleConfig: googlehandler.Config{}, GoogleClient: http.DefaultClient,
	})
	vaultRouter := vaultServer.Router()
	return &system{t: t, redis: redisServer, oauth: oauthRouter, vault: vaultRouter, browser: testsupport.NewBrowser(t, vaultRouter), clientID: clientID}
}

func allScopes() []string {
	return []string{
		"openid", "profile", "email",
		"calendar:read", "calendar:write", "contacts:read", "contacts:write",
		"photos:read", "photos:write", "files:read", "files:write",
	}
}

func (system *system) signUp(account *testsupport.Account) {
	system.t.Helper()
	sent := system.browser.Do("POST", "/vault/signup/send-code", map[string]any{"email": account.Email}, nil)
	system.browser.Do("POST", "/vault/signup/verify-code", map[string]any{"email": account.Email, "code": sent.Body["code"]}, nil)
	created := system.browser.Do("POST", "/vault/signup", account.SignupRequest(), nil)
	if created.Status != 200 {
		system.t.Fatalf("signup: %d %s", created.Status, created.Raw)
	}
}

// pkce returns a verifier and its S256 challenge.
func pkce() (string, string) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:])
}

// authorizeParams builds an authorization request for an install.
func (system *system) authorizeParams(install testsupport.Install, challenge string, scope string) url.Values {
	return url.Values{
		"client_id": {system.clientID}, "redirect_uri": {appRedirect}, "response_type": {"code"},
		"scope": {scope}, "state": {"state-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"install_id": {install.ID}, "install_enc_pub": {base64.RawURLEncoding.EncodeToString(install.EncPub[:])},
		"install_sign_pub": {base64.RawURLEncoding.EncodeToString(install.SignPub)}, "install_name": {"Test app"},
	}
}

// authorize runs GET /oauth/authorize and returns the redirect location.
func (system *system) authorize(params url.Values) *url.URL {
	system.t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
	recorder := httptest.NewRecorder()
	system.oauth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusFound {
		system.t.Fatalf("authorize: status %d", recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		system.t.Fatal(err)
	}
	return location
}

func hasPrefix(text, prefix string) bool {
	return strings.HasPrefix(text, prefix)
}

func (system *system) exchange(code, verifier string) testsupport.Response {
	return testsupport.Form(system.oauth, "/oauth/token", map[string]string{
		"grant_type": "authorization_code", "code": code, "redirect_uri": appRedirect,
		"client_id": system.clientID, "code_verifier": verifier,
	}, nil)
}

func (system *system) refresh(refreshToken string) testsupport.Response {
	return testsupport.Form(system.oauth, "/oauth/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": system.clientID,
	}, nil)
}

// introspect asks about subject, authenticating with bearer.
func (system *system) introspect(subject, bearer string) testsupport.Response {
	return testsupport.Form(system.oauth, "/oauth/introspect", map[string]string{"token": subject},
		map[string]string{"Authorization": "Bearer " + bearer})
}

func installRecord(installID string) models.RecordID {
	return models.NewRecordID("install", installID)
}

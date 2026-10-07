package flowtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
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
		Debug: true, PreloginSecret: []byte("secret"), AuthenticatorClientID: "neoworks-authenticator",
	}, testSurreal.Store, redis, issuer, mail.NewSender(mail.Config{}), vaulthandler.NoEscrow{})
	if err := testSurreal.PublishCollections(testsupport.TestCollections); err != nil {
		t.Fatal(err)
	}
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
		"@neoworks/calendar:read", "@neoworks/calendar:write", "@neoworks/contacts:read", "@neoworks/contacts:write",
		"@neoworks/photos:read", "@neoworks/photos:write", "@neoworks/files:read", "@neoworks/files:write",
		"@neoworks/calendar:share", "@neoworks/contacts:share",
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

// freshAccount signs up an account with a unique email.
func (system *system) freshAccount(label string) *testsupport.Account {
	system.t.Helper()
	account := testsupport.NewAccount(label + "-" + testsupport.NewAccount("x@example.com").UserID[:8] + "@example.com")
	system.signUp(account)
	return account
}

// issueTokens runs authorize, consent and the code exchange for a read grant on
// the account's photos root.
func (system *system) issueTokens(account *testsupport.Account) testsupport.Response {
	system.t.Helper()
	install := testsupport.NewInstall()
	verifier, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "@neoworks/photos:read"))
	body := consentFor(account, install, system.clientID, challengeID(location), []string{"@neoworks/photos:read"}, map[string]string{"@neoworks/photos": "read"})
	consent := system.browser.Do("POST", "/vault/consent", body, nil)
	if consent.Status != 200 {
		system.t.Fatalf("consent: %d %s", consent.Status, consent.Raw)
	}
	redirect, _ := url.Parse(consent.Body["redirect"].(string))
	issued := system.exchange(redirect.Query().Get("code"), verifier)
	if issued.Status != 200 {
		system.t.Fatalf("token: %d %s", issued.Status, issued.Raw)
	}
	return issued
}

func (system *system) getJSON(path string) map[string]any {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	system.oauth.ServeHTTP(recorder, request)
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return body
}

// verifyWithJWK verifies an ES256 token against a public JWK.
func verifyWithJWK(rawToken string, key map[string]any) (jwt.MapClaims, error) {
	xBytes, _ := base64.RawURLEncoding.DecodeString(key["x"].(string))
	yBytes, _ := base64.RawURLEncoding.DecodeString(key["y"].(string))
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(rawToken, claims, func(*jwt.Token) (any, error) { return publicKey, nil }, jwt.WithValidMethods([]string{"ES256"}))
	return claims, err
}

// createRoots runs a consent for every test collection so the account owns
// their roots, as after using its first apps. The account must be the one
// signed in.
func (system *system) createRoots(account *testsupport.Account) {
	system.t.Helper()
	install := testsupport.NewInstall()
	_, challenge := pkce()
	roles := map[string]string{}
	grantScopes := []string{}
	for _, collection := range testsupport.TestCollections {
		roles[collection] = "write"
		grantScopes = append(grantScopes, collection+":read", collection+":write")
	}
	location := system.authorize(system.authorizeParams(install, challenge, strings.Join(grantScopes, " ")))
	body := consentFor(account, install, system.clientID, challengeID(location), grantScopes, roles)
	if response := system.browser.Do("POST", "/vault/consent", body, nil); response.Status != 200 {
		system.t.Fatalf("consent creating roots: %d %s", response.Status, response.Raw)
	}
	account.CommitGrants()
}

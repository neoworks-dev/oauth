package google

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/handlers/oauth"
	"github.com/neoworks/oauth/internal/tokens"
)

type noRevocations struct{}

func (noRevocations) IsRevoked(context.Context, string) (bool, error) { return false, nil }

type proxyFixture struct {
	router   http.Handler
	issuer   *tokens.Issuer
	received []url.Values
	upstream *httptest.Server
	status   int
	reply    string
}

func newProxyFixture(t *testing.T, config Config) *proxyFixture {
	t.Helper()
	fix := &proxyFixture{status: http.StatusOK, reply: `{"access_token":"google-access","refresh_token":"google-refresh","expires_in":3599,"scope":"calendar","token_type":"Bearer","id_token":"must-not-pass"}`}
	fix.upstream = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		fix.received = append(fix.received, request.PostForm)
		response.WriteHeader(fix.status)
		_, _ = response.Write([]byte(fix.reply))
	}))
	t.Cleanup(fix.upstream.Close)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fix.issuer = tokens.NewIssuer(key, "http://oauth.test")
	config.TokenEndpoint = fix.upstream.URL
	router := chi.NewRouter()
	NewHandler(config, http.DefaultClient).Register(router, oauth.RequireBearer(fix.issuer, noRevocations{}))
	fix.router = router
	return fix
}

func testConfig() Config {
	return Config{
		ClientID: "google-client", ClientSecret: "google-secret",
		AllowedRedirectURIs: []string{"https://calendar.test/google/callback"},
		AcceptedScopes:      []string{"calendar:read", "calendar:write"},
	}
}

func (fix *proxyFixture) call(path string, body any, scopes ...string) (int, map[string]any) {
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	if len(scopes) > 0 {
		token, _, _ := fix.issuer.IssueAccessToken(tokens.AccessTokenParams{UserID: "u", ClientID: "app", Scopes: scopes, InstallID: "i"})
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	fix.router.ServeHTTP(recorder, request)
	var decoded map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder.Code, decoded
}

func TestExchangeAddsTheClientSecretAndRelaysOnlyTokenFields(t *testing.T) {
	fix := newProxyFixture(t, testConfig())
	status, body := fix.call("/google/token/exchange", map[string]string{"code": "auth-code", "redirectUri": "https://calendar.test/google/callback"}, "calendar:read")
	if status != 200 || body["refresh_token"] != "google-refresh" || body["access_token"] != "google-access" {
		t.Fatalf("exchange: %d %v", status, body)
	}
	if _, leaked := body["id_token"]; leaked {
		t.Fatal("only token fields may be relayed")
	}
	sent := fix.received[0]
	if sent.Get("client_secret") != "google-secret" || sent.Get("client_id") != "google-client" ||
		sent.Get("code") != "auth-code" || sent.Get("grant_type") != "authorization_code" {
		t.Fatalf("upstream request %v", sent)
	}
}

func TestRefreshForwardsTheRefreshToken(t *testing.T) {
	fix := newProxyFixture(t, testConfig())
	status, _ := fix.call("/google/token/refresh", map[string]string{"refreshToken": "old-refresh"}, "calendar:write")
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	sent := fix.received[0]
	if sent.Get("grant_type") != "refresh_token" || sent.Get("refresh_token") != "old-refresh" || sent.Get("client_secret") != "google-secret" {
		t.Fatalf("upstream request %v", sent)
	}
}

func TestProxyChecksTheCallerAndTheRequest(t *testing.T) {
	fix := newProxyFixture(t, testConfig())
	exchange := map[string]string{"code": "c", "redirectUri": "https://calendar.test/google/callback"}
	cases := []struct {
		name   string
		path   string
		body   any
		scopes []string
		want   int
	}{
		{"no token", "/google/token/exchange", exchange, nil, 401},
		{"wrong scope", "/google/token/exchange", exchange, []string{"photos:read"}, 403},
		{"redirect not allowed", "/google/token/exchange", map[string]string{"code": "c", "redirectUri": "https://evil.test/cb"}, []string{"calendar:read"}, 400},
		{"missing code", "/google/token/exchange", map[string]string{"redirectUri": "https://calendar.test/google/callback"}, []string{"calendar:read"}, 400},
		{"missing refresh token", "/google/token/refresh", map[string]string{}, []string{"calendar:read"}, 400},
	}
	for _, testCase := range cases {
		if status, _ := fix.call(testCase.path, testCase.body, testCase.scopes...); status != testCase.want {
			t.Errorf("%s: status %d, want %d", testCase.name, status, testCase.want)
		}
	}
	if len(fix.received) != 0 {
		t.Fatal("rejected requests must never reach Google")
	}
}

func TestProxyIsUnavailableWithoutCredentials(t *testing.T) {
	fix := newProxyFixture(t, Config{})
	status, _ := fix.call("/google/token/refresh", map[string]string{"refreshToken": "r"}, "calendar:read")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status %d", status)
	}
}

func TestUpstreamErrorsAreRelayedOrReportedAsBadGateway(t *testing.T) {
	fix := newProxyFixture(t, testConfig())
	fix.status, fix.reply = http.StatusBadRequest, `{"error":"invalid_grant","error_description":"Bad Request","debug":"drop me"}`
	status, body := fix.call("/google/token/refresh", map[string]string{"refreshToken": "r"}, "calendar:read")
	if status != 400 || body["error"] != "invalid_grant" || body["debug"] != nil {
		t.Fatalf("client errors pass through: %d %v", status, body)
	}
	fix.status, fix.reply = http.StatusInternalServerError, `<html>oops refresh-token-in-error</html>`
	status, body = fix.call("/google/token/refresh", map[string]string{"refreshToken": "r"}, "calendar:read")
	if status != http.StatusBadGateway {
		t.Fatalf("server errors become a bad gateway: %d %v", status, body)
	}
	fix.status, fix.reply = http.StatusOK, `not json`
	if status, _ := fix.call("/google/token/refresh", map[string]string{"refreshToken": "r"}, "calendar:read"); status == 200 {
		t.Fatal("an unreadable answer must not look like success")
	}
}

func TestProxyNeverLogsTokens(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	fix := newProxyFixture(t, testConfig())
	fix.call("/google/token/exchange", map[string]string{"code": "secret-auth-code", "redirectUri": "https://calendar.test/google/callback"}, "calendar:read")
	fix.call("/google/token/refresh", map[string]string{"refreshToken": "secret-refresh-token"}, "calendar:read")
	for _, secret := range []string{"secret-auth-code", "secret-refresh-token", "google-secret", "google-refresh", "google-access"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log output contains %q", secret)
		}
	}
}

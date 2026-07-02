package fedcm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/oauth"
)

type fakeStore struct{ redirectURIs []string }

func (f fakeStore) GetUserByID(context.Context, string) (*oauth.User, error) {
	return nil, errors.New("not used")
}
func (f fakeStore) GetClient(context.Context, string) (*oauth.Client, error) {
	if f.redirectURIs == nil {
		return nil, errors.New("client not found")
	}
	return &oauth.Client{RedirectURIs: f.redirectURIs}, nil
}

func newRouter(t *testing.T) chi.Router {
	t.Helper()
	router := chi.NewRouter()
	NewHandler(nil, nil, nil, "https://auth.example").Register(router)
	return router
}

func TestWellKnownListsConfigURL(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/.well-known/web-identity", nil)
	recorder := httptest.NewRecorder()
	newRouter(t).ServeHTTP(recorder, request)

	var body struct {
		ProviderURLs []string `json:"provider_urls"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.ProviderURLs) != 1 || !strings.HasSuffix(body.ProviderURLs[0], "/fedcm/config.json") {
		t.Fatalf("provider_urls = %v", body.ProviderURLs)
	}
}

func TestConfigRequiresWebIdentityHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/fedcm/config.json", nil)
	recorder := httptest.NewRecorder()
	newRouter(t).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("without Sec-Fetch-Dest: status = %d, want 400", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/fedcm/config.json", nil)
	request.Header.Set("Sec-Fetch-Dest", "webidentity")
	recorder = httptest.NewRecorder()
	newRouter(t).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("with header: status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "id_assertion_endpoint") {
		t.Error("config missing id_assertion_endpoint")
	}
}

func TestAccountsEmptyWithoutSession(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil)
	request.Header.Set("Sec-Fetch-Dest", "webidentity")
	recorder := httptest.NewRecorder()
	newRouter(t).ServeHTTP(recorder, request)

	var body struct {
		Accounts []any `json:"accounts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Accounts) != 0 {
		t.Fatalf("expected no accounts without a session, got %d", len(body.Accounts))
	}
}

func TestAssertionRejectsOriginNotInClientRedirects(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(fakeStore{redirectURIs: []string{"https://app.example/cb"}}, nil, nil, "https://auth.example").Register(router)

	body := strings.NewReader("client_id=app")
	request := httptest.NewRequest(http.MethodPost, "/fedcm/assertion", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("Sec-Fetch-Dest", "webidentity")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

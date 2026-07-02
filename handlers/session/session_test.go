package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/oauth"
)

// fakeStore returns a fixed client for any id, or an error when redirectURIs is nil.
type fakeStore struct {
	redirectURIs []string
}

func (f fakeStore) GetUserByID(context.Context, string) (*oauth.User, error) {
	return nil, errors.New("not used")
}
func (f fakeStore) GetClient(context.Context, string) (*oauth.Client, error) {
	if f.redirectURIs == nil {
		return nil, errors.New("client not found")
	}
	return &oauth.Client{RedirectURIs: f.redirectURIs}, nil
}

func TestSessionUnauthenticatedWithoutCookie(t *testing.T) {
	router := chi.NewRouter()
	// nil store/redis are never reached: the no-cookie path returns first.
	NewHandler(nil, nil).Register(router)

	request := httptest.NewRequest(http.MethodGet, "/session", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var resp sessionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Authenticated {
		t.Error("expected authenticated=false without a session cookie")
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Error("session must not be cached")
	}
}

func TestBridgeRejectsOriginNotInClientRedirects(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(fakeStore{redirectURIs: []string{"https://app.example/callback"}}, nil).Register(router)

	request := httptest.NewRequest(http.MethodGet,
		"/auth/session-bridge?client_id=app&origin=https://evil.example", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestBridgeRendersForRegisteredOrigin(t *testing.T) {
	router := chi.NewRouter()
	// Origin is derived from the client's redirect URI.
	NewHandler(fakeStore{redirectURIs: []string{"https://app.example/auth/callback"}}, nil).Register(router)

	request := httptest.NewRequest(http.MethodGet,
		"/auth/session-bridge?client_id=app&origin=https://app.example", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if csp := recorder.Header().Get("Content-Security-Policy"); csp != "frame-ancestors https://app.example" {
		t.Errorf("unexpected CSP: %q", csp)
	}
}

func TestBridgeRejectsUnknownClient(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(fakeStore{redirectURIs: nil}, nil).Register(router)

	request := httptest.NewRequest(http.MethodGet,
		"/auth/session-bridge?client_id=ghost&origin=https://app.example", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

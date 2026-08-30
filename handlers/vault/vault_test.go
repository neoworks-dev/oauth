package vault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/oauth"
)

// fakeStore returns a fixed client for any id, or an error when redirectURIs is nil.
type fakeStore struct {
	redirectURIs []string
}

func (f fakeStore) GetClient(context.Context, string) (*oauth.Client, error) {
	if f.redirectURIs == nil {
		return nil, errors.New("client not found")
	}
	return &oauth.Client{RedirectURIs: f.redirectURIs}, nil
}

func serve(t *testing.T, store store, target string) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	NewHandler(store).Register(router)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	return recorder
}

// The frame is framable by anyone: capability comes from the embedder's access
// token, so filtering the embedding origin would grant nothing.
func TestVaultFrameIsFramableByAnyOrigin(t *testing.T) {
	recorder := serve(t, fakeStore{redirectURIs: []string{"https://app.example/callback"}},
		"/vault?client_id=app")

	if csp := recorder.Header().Get("Content-Security-Policy"); csp != "frame-ancestors *" {
		t.Errorf("CSP = %q, want frame-ancestors *", csp)
	}
}

// The unlock window names the key the account master key is sealed to, so it
// accepts that message only from the client's registered redirect origins.
func TestUnlockWindowAllowsOnlyRegisteredRedirectOrigins(t *testing.T) {
	recorder := serve(t, fakeStore{redirectURIs: []string{
		"https://calendar.example/callback",
		"http://localhost:5175/callback",
		"dev.neoworks.calendar://callback",
	}}, "/vault/unlock?client_id=app")

	body := recorder.Body.String()
	for _, want := range []string{"https://calendar.example", "http://localhost:5175"} {
		if !strings.Contains(body, want) {
			t.Errorf("unlock page does not allow %q", want)
		}
		// An origin, not the redirect URI it came from: postMessage compares
		// scheme://host[:port] and a trailing path would never match.
		if strings.Contains(body, want+"/callback") {
			t.Errorf("allowed origin %q kept its redirect path", want)
		}
	}
}

// A top-level document on purpose, so the address bar states the origin.
func TestUnlockWindowRefusesToBeFramed(t *testing.T) {
	recorder := serve(t, fakeStore{redirectURIs: []string{"https://app.example/callback"}},
		"/vault/unlock?client_id=app")

	if csp := recorder.Header().Get("Content-Security-Policy"); csp != "frame-ancestors 'none'" {
		t.Errorf("CSP = %q, want frame-ancestors 'none'", csp)
	}
	if xfo := recorder.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", xfo)
	}
}

// An unknown client must not fall back to an empty-but-permissive allowlist.
func TestUnlockOriginsAreEmptyForUnknownClient(t *testing.T) {
	if got := unlockOrigins(nil); len(got) != 0 {
		t.Fatalf("unlockOrigins(nil) = %v, want empty", got)
	}

	recorder := serve(t, fakeStore{redirectURIs: nil}, "/vault/unlock?client_id=ghost")
	if !strings.Contains(recorder.Body.String(), "[]") {
		t.Error("unknown client should render an empty allowed-origins list")
	}
}

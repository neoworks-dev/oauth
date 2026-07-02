package static

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	// Blank imports force each handler package's init() to run, which parses
	// every auth-page template via template.Must — a malformed template (e.g. a
	// broken {{if}} after the redesign) panics here rather than in production.
	_ "github.com/neoworks/oauth/handlers"
	_ "github.com/neoworks/oauth/handlers/account"
	_ "github.com/neoworks/oauth/handlers/auth"
	_ "github.com/neoworks/oauth/handlers/oauth"
	_ "github.com/neoworks/oauth/handlers/vault"
)

func TestServesSharedAssets(t *testing.T) {
	router := chi.NewRouter()
	NewHandler().Register(router)

	cases := []struct {
		path        string
		contentType string
	}{
		{"/auth/static/neoworks.css", "text/css; charset=utf-8"},
		{"/auth/static/geist-400.woff2", "font/woff2"},
		{"/auth/static/geist-500.woff2", "font/woff2"},
		{"/auth/static/geist-600.woff2", "font/woff2"},
	}

	for _, tc := range cases {
		request := httptest.NewRequest(http.MethodGet, tc.path, nil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", tc.path, recorder.Code)
		}
		if got := recorder.Header().Get("Content-Type"); got != tc.contentType {
			t.Errorf("%s: content-type = %q, want %q", tc.path, got, tc.contentType)
		}
		if recorder.Body.Len() == 0 {
			t.Errorf("%s: empty body", tc.path)
		}
		if recorder.Header().Get("Cache-Control") == "" {
			t.Errorf("%s: missing Cache-Control", tc.path)
		}
	}
}

func TestCSSReferencesDesignTokens(t *testing.T) {
	data, err := assets.ReadFile("assets/neoworks.css")
	if err != nil {
		t.Fatalf("read css: %v", err)
	}
	css := string(data)
	for _, token := range []string{"--primary", "--surface-input", "@font-face", "prefers-color-scheme"} {
		if !strings.Contains(css, token) {
			t.Errorf("neoworks.css missing %q", token)
		}
	}
}

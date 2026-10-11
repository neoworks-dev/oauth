package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestDiscoveryAdvertisesOnlyTheFixedScopes(t *testing.T) {
	router := chi.NewRouter()
	NewDiscoveryHandler("http://oauth.test/").Register(router)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	var document struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if strings.Join(document.ScopesSupported, " ") != "openid profile email" {
		t.Fatalf("collection scopes are open-ended and must not be listed: %v", document.ScopesSupported)
	}
}

package escrow

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

func call(handler http.Handler, method, path, token string, body any) (int, map[string]any) {
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var decoded map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder.Code, decoded
}

func TestHTTPRequiresTheServiceToken(t *testing.T) {
	fix := newFixture(t)
	handler := NewHandler(fix.service, "secret-token")
	for _, token := range []string{"", "wrong", "secret-token "} {
		if status, _ := call(handler, "GET", "/v1/public-key", token, nil); status != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d", token, status)
		}
	}
	if status, _ := call(NewHandler(fix.service, ""), "GET", "/v1/public-key", "", nil); status != http.StatusUnauthorized {
		t.Fatal("an unconfigured token must lock the API")
	}
	status, body := call(handler, "GET", "/v1/public-key", "secret-token", nil)
	if status != http.StatusOK || body["publicKey"] == "" {
		t.Fatalf("status %d body %v", status, body)
	}
}

func TestHTTPRecoveryRoundTrip(t *testing.T) {
	fix := newFixture(t)
	handler := NewHandler(fix.service, "t")
	sealed, _ := box.SealAnonymous(nil, fix.amk, &fix.service.key.Public, rand.Reader)
	status, _ := call(handler, "PUT", "/v1/escrow/user-1", "t", map[string]string{"sealedAmk": base64.RawURLEncoding.EncodeToString(sealed)})
	if status != 200 {
		t.Fatalf("enroll: %d", status)
	}
	tempPublic, tempSecret := newTempKeys(t)
	status, started := call(handler, "POST", "/v1/recovery", "t", map[string]string{
		"userId": "user-1", "email": "ada@example.com", "tempPub": base64.RawURLEncoding.EncodeToString(tempPublic[:]),
	})
	if status != 200 {
		t.Fatalf("start: %d %v", status, started)
	}
	claimPath := "/v1/recovery/" + started["id"].(string) + "/claim"
	claim := map[string]string{"userId": "user-1", "claimSecret": started["claimSecret"].(string)}
	if status, body := call(handler, "POST", claimPath, "t", claim); status != http.StatusTooEarly {
		t.Fatalf("early claim: %d %v", status, body)
	}
	fix.now = fix.now.Add(8 * 24 * time.Hour)
	status, released := call(handler, "POST", claimPath, "t", claim)
	if status != 200 {
		t.Fatalf("claim: %d %v", status, released)
	}
	sealedAmk, _ := base64.RawURLEncoding.DecodeString(released["sealedAmk"].(string))
	amk, ok := box.OpenAnonymous(nil, sealedAmk, tempPublic, tempSecret)
	if !ok || string(amk) != string(fix.amk) {
		t.Fatal("the AMK must come back sealed to the temporary key")
	}
}

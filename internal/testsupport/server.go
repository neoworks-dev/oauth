package testsupport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Browser is a minimal cookie-keeping HTTP client over a handler, with the
// header the vault's CSRF check requires.
type Browser struct {
	T       testing.TB
	Handler http.Handler
	Cookies map[string]string
}

func NewBrowser(t testing.TB, handler http.Handler) *Browser {
	return &Browser{T: t, Handler: handler, Cookies: map[string]string{}}
}

// Response is a decoded JSON reply.
type Response struct {
	Status int
	Header http.Header
	Body   map[string]any
	Raw    []byte
}

// Do sends a JSON request and stores any cookies the reply sets.
func (browser *Browser) Do(method, path string, body any, headers map[string]string) Response {
	browser.T.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-NW-Vault", "1")
	for name, value := range browser.Cookies {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	browser.Handler.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		browser.storeCookie(cookie)
	}
	return decode(recorder)
}

func (browser *Browser) storeCookie(cookie *http.Cookie) {
	if cookie.MaxAge < 0 || cookie.Value == "" {
		delete(browser.Cookies, cookie.Name)
		return
	}
	browser.Cookies[cookie.Name] = cookie.Value
}

func decode(recorder *httptest.ResponseRecorder) Response {
	response := Response{Status: recorder.Code, Header: recorder.Header(), Raw: recorder.Body.Bytes()}
	_ = json.Unmarshal(response.Raw, &response.Body)
	return response
}

// Form posts a form to a handler, as the token endpoint expects.
func Form(handler http.Handler, path string, values map[string]string, headers map[string]string) Response {
	form := make([]byte, 0, 128)
	for name, value := range values {
		if len(form) > 0 {
			form = append(form, '&')
		}
		form = append(form, []byte(queryEscape(name)+"="+queryEscape(value))...)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return decode(recorder)
}

func queryEscape(text string) string {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	query := request.URL.Query()
	query.Set("k", text)
	return query.Encode()[2:]
}

// NewBrowserFor starts a second browser against the same handler, with its own cookies.
func NewBrowserFor(t testing.TB, handler http.Handler) *Browser {
	return NewBrowser(t, handler)
}

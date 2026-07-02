package oauth

import (
	_ "embed"
	"html/template"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

type ErrorPageHandler struct{}

func NewErrorPageHandler() *ErrorPageHandler {
	return &ErrorPageHandler{}
}

func (h *ErrorPageHandler) Register(r chi.Router) {
	r.Get("/oauth/error", h.serveError)
}

//go:embed templates/error.html
var errorTemplate string
var errorTmpl = template.Must(template.New("error").Parse(errorTemplate))

// RedirectToErrorPage sends the browser to the local /oauth/error page. Use this
// for failures that happen before redirect_uri can be trusted (or has no
// meaningful client to bounce back to), so the user sees an explanation
// instead of a bare status code or a closed window.
func RedirectToErrorPage(w http.ResponseWriter, r *http.Request, errorCode, description string) {
	u := &url.URL{
		Scheme: "http",
		Host:   r.Host,
		Path:   "/oauth/error",
	}

	q := u.Query()
	q.Set("error", errorCode)
	if description != "" {
		q.Set("error_description", description)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *ErrorPageHandler) serveError(w http.ResponseWriter, r *http.Request) {
	errorCode := r.URL.Query().Get("error")
	if errorCode == "" {
		errorCode = "server_error"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = errorTmpl.Execute(w, map[string]string{
		"Error":       errorCode,
		"Description": r.URL.Query().Get("error_description"),
	})
}

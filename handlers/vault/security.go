package vault

import (
	"net/http"
	"net/url"
	"strings"
)

const csrfHeader = "X-NW-Vault"

// contentSecurityPolicy forbids inline script and style, third-party loads,
// framing and unsafe DOM sinks. Wasm is allowed for libsodium.
func contentSecurityPolicy(config Config) string {
	connectSources := "'self'"
	if config.APIURL != "" {
		connectSources += " " + config.APIURL
	}
	directives := []string{
		"default-src 'none'",
		"script-src 'self' 'wasm-unsafe-eval'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src " + connectSources,
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"object-src 'none'",
		"require-trusted-types-for 'script'",
		"trusted-types 'none'",
	}
	return strings.Join(directives, "; ")
}

// securityHeaders applies the vault origin's hardening headers to every response.
func securityHeaders(config Config) func(http.Handler) http.Handler {
	policy := contentSecurityPolicy(config)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			header := response.Header()
			header.Set("Content-Security-Policy", policy)
			header.Set("X-Frame-Options", "DENY")
			header.Set("X-Content-Type-Options", "nosniff")
			header.Set("Referrer-Policy", "no-referrer")
			header.Set("Cross-Origin-Opener-Policy", "same-origin")
			header.Set("Cross-Origin-Resource-Policy", "same-origin")
			header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
			if config.SecureCookies {
				header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(response, request)
		})
	}
}

func isStateChanging(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

// requireSameOriginJSON protects the cookie-authenticated API against CSRF. A
// state-changing request must come from this origin's own scripts, which set a
// custom header that cross-site requests cannot send without a CORS preflight.
// Requests that authenticate with a bearer token do not use cookies and are exempt.
func requireSameOriginJSON(vaultURL string) func(http.Handler) http.Handler {
	expectedOrigin := originOf(vaultURL)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if isStateChanging(request.Method) && !passesCSRF(request, expectedOrigin) {
				writeError(response, http.StatusForbidden, "csrf")
				return
			}
			next.ServeHTTP(response, request)
		})
	}
}

func passesCSRF(request *http.Request, expectedOrigin string) bool {
	if strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
		return true
	}
	if request.Header.Get(csrfHeader) != "1" {
		return false
	}
	origin := request.Header.Get("Origin")
	if origin != "" && origin != expectedOrigin {
		return false
	}
	site := request.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

func originOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

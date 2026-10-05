// Package config resolves environment-driven settings and service URLs.
package config

import "os"

// Env returns the environment variable, or fallback when it is unset or empty.
func Env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

// BaseDomain is the root domain every service hangs off.
func BaseDomain() string {
	return Env("BASE_DOMAIN", "neoworks.localhost")
}

// BaseScheme is the URL scheme of every service.
func BaseScheme() string {
	return Env("BASE_SCHEME", "https")
}

// BasePort is the explicit port of every service origin; empty means the
// scheme's default port.
func BasePort() string {
	return Env("BASE_PORT", "")
}

// ServiceURL returns the base URL of a service subdomain, for example
// ServiceURL("vault") is https://vault.neoworks.localhost:8443 when BASE_PORT
// is 8443. The port is omitted when it is the scheme's default.
func ServiceURL(subdomain string) string {
	host := BaseDomain()
	if subdomain != "" {
		host = subdomain + "." + host
	}
	return BaseScheme() + "://" + host + portSuffix(BaseScheme(), BasePort())
}

// portSuffix returns ":port", or "" when the port is empty or the scheme's default.
func portSuffix(scheme, port string) string {
	if port == "" {
		return ""
	}
	if scheme == "https" && port == "443" {
		return ""
	}
	if scheme == "http" && port == "80" {
		return ""
	}
	return ":" + port
}

// SecureCookies reports whether cookies may carry the Secure attribute and the
// __Host- prefix. Plain-HTTP development origins cannot.
func SecureCookies() bool {
	return BaseScheme() == "https"
}

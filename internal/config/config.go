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

// ServiceURL returns the base URL of a service subdomain, for example
// ServiceURL("vault") is https://vault.neoworks.localhost.
func ServiceURL(subdomain string) string {
	if subdomain == "" {
		return BaseScheme() + "://" + BaseDomain()
	}
	return BaseScheme() + "://" + subdomain + "." + BaseDomain()
}

// SecureCookies reports whether cookies may carry the Secure attribute and the
// __Host- prefix. Plain-HTTP development origins cannot.
func SecureCookies() bool {
	return BaseScheme() == "https"
}

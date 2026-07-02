// Package origins derives the set of web origins allowed to use the
// "Sign in with NeoWorks" prompt from a registered OAuth client's redirect
// URIs. This reuses the same trust source as the authorize flow — an app may
// prompt from exactly the origins it already registered to receive sign-ins —
// so the allowlist needs no separate configuration and stays correct as clients
// are added or changed.
package origins

import (
	"net/url"
	"slices"
)

// FromRedirectURIs returns the unique scheme://host[:port] origins of the given
// redirect URIs. Unparseable entries are skipped.
func FromRedirectURIs(redirectURIs []string) []string {
	seen := make(map[string]struct{}, len(redirectURIs))
	result := make([]string, 0, len(redirectURIs))
	for _, raw := range redirectURIs {
		origin := originOf(raw)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		result = append(result, origin)
	}
	return result
}

// Allows reports whether origin is one of the redirect URIs' origins.
func Allows(redirectURIs []string, origin string) bool {
	if origin == "" {
		return false
	}
	return slices.Contains(FromRedirectURIs(redirectURIs), origin)
}

func originOf(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

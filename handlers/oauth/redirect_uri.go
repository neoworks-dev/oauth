package oauth

import (
	"net/url"
	"slices"
)

// loopbackRedirect is a loopback redirect URI with its port left out.
type loopbackRedirect struct {
	hostname string
	path     string
	query    string
}

// redirectURIRegistered reports whether requested is one of the client's
// redirect URIs. A loopback IP redirect matches on any port (RFC 8252 section
// 7.3), because native apps listen on a port the system picks at runtime.
func redirectURIRegistered(registered []string, requested string) bool {
	if slices.Contains(registered, requested) {
		return true
	}
	requestedLoopback, ok := parseLoopbackRedirect(requested)
	if !ok {
		return false
	}
	for _, candidate := range registered {
		candidateLoopback, isLoopback := parseLoopbackRedirect(candidate)
		if isLoopback && candidateLoopback == requestedLoopback {
			return true
		}
	}
	return false
}

// parseLoopbackRedirect accepts http URIs on a loopback IP literal. localhost
// is not one: it can resolve to another host.
func parseLoopbackRedirect(uri string) (loopbackRedirect, bool) {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Fragment != "" {
		return loopbackRedirect{}, false
	}
	hostname := parsed.Hostname()
	if hostname != "127.0.0.1" && hostname != "::1" {
		return loopbackRedirect{}, false
	}
	return loopbackRedirect{hostname: hostname, path: parsed.EscapedPath(), query: parsed.RawQuery}, true
}

// Package scopes defines the scopes the authorization server grants.
package scopes

import (
	"slices"
	"strings"
)

// Collections are the data collections an app can be granted access to.
var Collections = []string{"calendar", "contacts", "photos", "files"}

var identityScopes = []string{"openid", "profile", "email"}

// IsKnown reports whether a scope is an identity scope or <collection>:read|write.
func IsKnown(scope string) bool {
	if slices.Contains(identityScopes, scope) {
		return true
	}
	collection, action, found := strings.Cut(scope, ":")
	if !found {
		return false
	}
	if action != "read" && action != "write" {
		return false
	}
	return slices.Contains(Collections, collection)
}

// AllKnown reports whether every requested scope is known.
func AllKnown(requested []string) bool {
	for _, scope := range requested {
		if !IsKnown(scope) {
			return false
		}
	}
	return true
}

// Subset reports whether every requested scope is in allowed.
func Subset(allowed, requested []string) bool {
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return true
}

// CollectionRoles maps each requested collection to the highest role its
// scopes allow: "write" if <collection>:write is present, else "read".
func CollectionRoles(requested []string) map[string]string {
	roles := map[string]string{}
	for _, scope := range requested {
		collection, action, found := strings.Cut(scope, ":")
		if !found || !slices.Contains(Collections, collection) {
			continue
		}
		if action == "write" || roles[collection] == "" {
			roles[collection] = action
		}
	}
	return roles
}

// WantsCollections reports whether any scope grants access to a collection.
func WantsCollections(requested []string) bool {
	return len(CollectionRoles(requested)) > 0
}

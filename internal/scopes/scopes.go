// Package scopes defines the scopes the authorization server grants.
package scopes

import (
	"regexp"
	"slices"
	"strings"
)

var (
	identityScopes           = []string{"openid", "profile", "email"}
	serviceScopes            = []string{"schemas:publish"}
	collectionSegmentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	collectionActions        = []string{"read", "write", "share"}
)

// ParseCollection splits a collection, the registry path `@scope/name` of the
// schema its nodes follow, into scope and name.
func ParseCollection(collection string) (scope, name string, ok bool) {
	path, hasAt := strings.CutPrefix(collection, "@")
	if !hasAt {
		return "", "", false
	}
	scope, name, hasSlash := strings.Cut(path, "/")
	if !hasSlash || !collectionSegmentPattern.MatchString(scope) || !collectionSegmentPattern.MatchString(name) {
		return "", "", false
	}
	return scope, name, true
}

func IsCollection(collection string) bool {
	_, _, ok := ParseCollection(collection)
	return ok
}

// collectionScope splits `<collection>:<action>`; ok is false for any other scope.
func collectionScope(scope string) (collection, action string, ok bool) {
	separator := strings.LastIndex(scope, ":")
	if separator < 0 {
		return "", "", false
	}
	collection, action = scope[:separator], scope[separator+1:]
	if !IsCollection(collection) || !slices.Contains(collectionActions, action) {
		return "", "", false
	}
	return collection, action, true
}

// IsKnown reports whether a scope is an identity scope, a service scope or
// <collection>:read|write|share.
func IsKnown(scope string) bool {
	if slices.Contains(identityScopes, scope) {
		return true
	}
	if slices.Contains(serviceScopes, scope) {
		return true
	}
	_, _, ok := collectionScope(scope)
	return ok
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

// Collections lists the collections the scopes name, once each.
func Collections(requested []string) []string {
	collections := []string{}
	for _, scope := range requested {
		collection, _, ok := collectionScope(scope)
		if ok && !slices.Contains(collections, collection) {
			collections = append(collections, collection)
		}
	}
	return collections
}

// CollectionRoles maps each requested collection to the highest role its
// scopes allow: "write" if <collection>:write is present, else "read".
func CollectionRoles(requested []string) map[string]string {
	roles := map[string]string{}
	for _, scope := range requested {
		collection, action, ok := collectionScope(scope)
		if !ok || action == "share" {
			continue
		}
		if action == "write" || roles[collection] == "" {
			roles[collection] = action
		}
	}
	return roles
}

// ShareCollections lists the collections whose `<collection>:share` scope is
// requested, which lets the app share them with other people.
func ShareCollections(requested []string) []string {
	shared := []string{}
	for _, scope := range requested {
		collection, action, ok := collectionScope(scope)
		if ok && action == "share" {
			shared = append(shared, collection)
		}
	}
	return shared
}

// SharesWithinRoles reports whether every share scope names a collection that
// also has a read or write scope, since sharing needs access to share.
func SharesWithinRoles(requested []string) bool {
	roles := CollectionRoles(requested)
	for _, collection := range ShareCollections(requested) {
		if roles[collection] == "" {
			return false
		}
	}
	return true
}

// WantsCollections reports whether any scope grants access to a collection.
func WantsCollections(requested []string) bool {
	return len(CollectionRoles(requested)) > 0
}

// ReadWrite are the read and write scopes of each collection, as the vault's
// own token carries them.
func ReadWrite(collections []string) []string {
	granted := make([]string, 0, 2*len(collections))
	for _, collection := range collections {
		granted = append(granted, collection+":read", collection+":write")
	}
	return granted
}

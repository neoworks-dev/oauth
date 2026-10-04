// Package ids validates client-generated identifiers.
package ids

import "regexp"

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// IsLowercaseUUIDv4 reports whether text is a lowercase UUIDv4.
func IsLowercaseUUIDv4(text string) bool {
	return uuidV4Pattern.MatchString(text)
}

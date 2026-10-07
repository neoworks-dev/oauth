package scopes

import "testing"

func TestIsKnown(t *testing.T) {
	known := []string{"openid", "profile", "email", "schemas:publish", "@neoworks/calendar:read", "@neoworks/calendar:share"}
	for _, scope := range known {
		if !IsKnown(scope) {
			t.Errorf("IsKnown(%q) = false, want true", scope)
		}
	}
	unknown := []string{"schemas:delete", "calendar:read", "@neoworks/calendar:admin", "@neoworks:read", ""}
	for _, scope := range unknown {
		if IsKnown(scope) {
			t.Errorf("IsKnown(%q) = true, want false", scope)
		}
	}
}

func TestServiceScopesNeedNoCollection(t *testing.T) {
	if WantsCollections([]string{"openid", "schemas:publish"}) {
		t.Error("schemas:publish must not count as a collection scope")
	}
}

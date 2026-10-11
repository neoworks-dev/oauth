package scopes

import (
	"slices"
	"testing"
)

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

func TestRetainKeepsCollectionsTheApprovalDoesNotMention(t *testing.T) {
	held := []string{"openid", "@neoworks/photos:read", "@neoworks/calendar:read", "@neoworks/calendar:write"}
	approved := []string{"email", "@neoworks/calendar:read"}
	got := Retain(held, approved)
	want := []string{"email", "@neoworks/calendar:read", "@neoworks/photos:read"}
	if !slices.Equal(got, want) {
		t.Errorf("Retain = %v, want %v", got, want)
	}
}

func TestWithoutCollectionDropsEveryScopeOfOneCollection(t *testing.T) {
	held := []string{"openid", "@neoworks/photos:read", "@neoworks/photos:share", "@neoworks/calendar:read"}
	got := WithoutCollection(held, "@neoworks/photos")
	want := []string{"openid", "@neoworks/calendar:read"}
	if !slices.Equal(got, want) {
		t.Errorf("WithoutCollection = %v, want %v", got, want)
	}
}

func TestHandlesListsTheOwnersOfCollectionsOnce(t *testing.T) {
	got := Handles([]string{"@neoworks/calendar", "@acme/recipes", "@neoworks/photos", "garbage"})
	if len(got) != 2 || got[0] != "neoworks" || got[1] != "acme" {
		t.Fatalf("handles: %v", got)
	}
}

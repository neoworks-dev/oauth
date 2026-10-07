package store_test

import (
	"context"
	"testing"
	"time"

	. "github.com/neoworks/oauth/internal/store"
)

func TestInstallConsentRoundTrip(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateAccount(ctx, sampleAccount("user-i", "install-owner@example.com")); err != nil {
		t.Fatalf("create account: %v", err)
	}
	calendarRoot, calendarOwner := sampleRoot("user-i", "root-user-i", "@neoworks/calendar")
	contactsRoot, contactsOwner := sampleRoot("user-i", "node-b", "@neoworks/contacts")
	consent := InstallConsent{
		Install:     Install{ID: "install-1", UserID: "user-i", ClientID: "photos", EncPub: "ZW5j", SignPub: "c2ln", Name: "Photos", CreatedAt: now},
		Certificate: Certificate{ID: "cert-1", Bytes: "Ynl0ZXM", Signature: "c2ln"},
		Roots:       []Node{calendarRoot, contactsRoot},
		RootGrants:  []AccessGrant{calendarOwner, contactsOwner},
		Grants: []AccessGrant{
			{NodeID: "root-user-i", PrincipalType: "install", PrincipalID: "install-1", Role: "read", Epoch: 1, WrappedKeys: "d3Jh", GrantedByType: "user", GrantedByID: "user-i", CertID: "cert-1", Signature: "c2ln", LogIndex: 1, CreatedAt: now, PrevHash: "AAAA", EntryHash: "aGFzaA", WrappedKeysHash: "a2V5cw"},
			{NodeID: "node-b", PrincipalType: "install", PrincipalID: "install-1", Role: "write", Facets: []uint32{0, 1}, Epoch: 2, WrappedKeys: "d3Jh", GrantedByType: "user", GrantedByID: "user-i", CertID: "cert-1", Signature: "c2ln", LogIndex: 1, CreatedAt: now, PrevHash: "AAAA", EntryHash: "aGFzaA", WrappedKeysHash: "a2V5cw"},
		},
	}
	if err := db.SaveInstallConsent(ctx, consent); err != nil {
		t.Fatalf("save consent: %v", err)
	}
	roots, err := db.RootCollections(ctx, "user-i")
	if err != nil || len(roots) != 2 {
		t.Fatalf("the consent should create both roots: %v err %v", roots, err)
	}
	owned, err := db.ListOwnerGrants(ctx, "user-i")
	if err != nil || len(owned) != 2 {
		t.Fatalf("the consent should store the owner grants: %+v err %v", owned, err)
	}
	consent.Roots, consent.RootGrants = nil, nil
	consent.Certificate.ID = "cert-2"
	for index := range consent.Grants {
		consent.Grants[index].LogIndex = 2
	}
	if err := db.SaveInstallConsent(ctx, consent); err != nil {
		t.Fatalf("saving again must replace grants: %v", err)
	}
	install, err := db.GetInstall(ctx, "install-1")
	if err != nil || install.UserID != "user-i" || install.ClientID != "photos" || install.RevokedAt != nil {
		t.Fatalf("unexpected install %+v err %v", install, err)
	}
	bundle, err := db.GetInstallGrantBundle(ctx, "install-1")
	if err != nil {
		t.Fatalf("grant bundle: %v", err)
	}
	if bundle.Certificate.Bytes != "Ynl0ZXM" || len(bundle.Grants) != 2 {
		t.Fatalf("unexpected bundle %+v", bundle)
	}
}

func TestDeviceRegistrationRefusesRevokedDevice(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	if err := db.RegisterDevice(ctx, "user-d", "device-1", "Laptop", "browser"); err != nil {
		t.Fatal(err)
	}
	if err := db.RegisterDevice(ctx, "user-d", "device-1", "Laptop", "browser"); err != nil {
		t.Fatalf("known device must register again: %v", err)
	}
	if err := db.RegisterDevice(ctx, "user-other", "device-1", "Laptop", "browser"); err != ErrRevoked {
		t.Fatalf("device of another user must be refused, got %v", err)
	}
	if err := testSurreal.Exec("UPDATE device:⟨device-1⟩ SET revoked_at = time::now()", nil); err != nil {
		t.Fatal(err)
	}
	active, err := db.IsDeviceActive(ctx, "user-d", "device-1")
	if err != nil || active {
		t.Fatalf("revoked device must be inactive, got %v %v", active, err)
	}
}

func TestRefreshTokenLifecycle(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	token := RefreshToken{ID: "rt-1", UserID: "user-r", ClientID: "photos", InstallID: "install-r", Scopes: []string{"photos:read"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := db.SaveRefreshToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetRefreshToken(ctx, "rt-1")
	if err != nil || loaded.InstallID != "install-r" || loaded.Used || loaded.Revoked {
		t.Fatalf("unexpected token %+v err %v", loaded, err)
	}
	if err := db.MarkRefreshTokenUsed(ctx, "rt-1"); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeRefreshTokensFor(ctx, "user-r", "photos"); err != nil {
		t.Fatal(err)
	}
	loaded, _ = db.GetRefreshToken(ctx, "rt-1")
	if !loaded.Used || !loaded.Revoked {
		t.Fatalf("token should be used and revoked: %+v", loaded)
	}
}

func TestTokenWithoutInstallHasEmptyInstall(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	token := RefreshToken{ID: "rt-2", UserID: "user-r2", ClientID: "photos", Scopes: []string{"openid"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := db.SaveRefreshToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetRefreshToken(ctx, "rt-2")
	if err != nil || loaded.InstallID != "" {
		t.Fatalf("unexpected token %+v err %v", loaded, err)
	}
}

func TestRotateBundleRequiresCurrentVersion(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	if err := db.CreateAccount(ctx, sampleAccount("user-rot", "rot@example.com")); err != nil {
		t.Fatal(err)
	}
	next := sampleAccount("user-rot", "rot@example.com").Bundle
	next.Version = 2
	next.AmkPassword = "bmV4dA"
	rotation := Rotation{UserID: "user-rot", ExpectedVersion: 1, AuthHash: "rotated", Bundle: next}
	if err := db.RotateBundle(ctx, rotation); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := db.RotateBundle(ctx, rotation); err != ErrConflict {
		t.Fatalf("replaying the same rotation must conflict, got %v", err)
	}
	bundle, _ := db.GetKeyBundle(ctx, "user-rot")
	user, _ := db.GetUserByID(ctx, "user-rot")
	if bundle.Version != 2 || bundle.AmkPassword != "bmV4dA" || user.AuthHash != "rotated" {
		t.Fatalf("unexpected state %+v %+v", bundle, user)
	}
}

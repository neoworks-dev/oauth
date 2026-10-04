package store_test

import (
	"context"
	"testing"
	"time"

	. "github.com/neoworks/oauth/internal/store"
)

func sampleAccount(userID, email string) NewAccount {
	now := time.Now().UTC()
	rootNode := Node{
		ID: "root-" + userID, OwnerID: userID, Collection: "calendar", Kind: "root", Epoch: 1,
		Content: []NodeFacet{{Facet: 0, Ciphertext: "c2VhbGVk"}}, BaseSeq: 0, Seq: 1,
		AuthorType: "user", AuthorID: userID, Signature: "c2ln", CreatedAt: now, UpdatedAt: now,
	}
	ownerGrant := AccessGrant{
		NodeID: rootNode.ID, PrincipalType: "user", PrincipalID: userID, Role: "write", Epoch: 1,
		WrappedKeys: "d3JhcHBlZA", GrantedByType: "user", GrantedByID: userID, Signature: "c2ln", CreatedAt: now,
		PrevHash: "AAAA", EntryHash: "aGFzaA", WrappedKeysHash: "a2V5cw",
	}
	return NewAccount{
		UserID: userID, Email: email, FirstName: "Ada", LastName: "Lovelace", AuthHash: "hash",
		Bundle: KeyBundle{
			UserID: userID, Version: 1, PwhashSalt: "c2FsdA", PwhashOps: 3, PwhashMem: 67108864,
			AmkPassword: "YQ", AmkRecovery: "Yg", IdentityPrivate: "Yw", EncPub: "ZA", SignPub: "ZQ", SelfSig: "Zg",
		},
		Device: Device{ID: "device-" + userID, Name: "Test browser", Kind: "browser"},
		Nodes:  []Node{rootNode},
		Grants: []AccessGrant{ownerGrant},
	}
}

func TestCreateAccountRoundTrip(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	account := sampleAccount("user-roundtrip", "ada@example.com")
	if err := db.CreateAccount(ctx, account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	user, err := db.GetUserByEmail(ctx, "ada@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if user.ID != "user-roundtrip" || user.AuthHash != "hash" || user.EscrowEnabled {
		t.Fatalf("unexpected user %+v", user)
	}
	bundle, err := db.GetKeyBundle(ctx, "user-roundtrip")
	if err != nil {
		t.Fatalf("get bundle: %v", err)
	}
	if bundle.Version != 1 || bundle.PwhashMem != 67108864 || bundle.EncPub != "ZA" {
		t.Fatalf("unexpected bundle %+v", bundle)
	}
	structure, err := db.ListStructure(ctx, "user-roundtrip")
	if err != nil || len(structure) != 1 || structure[0].ID != "root-user-roundtrip" {
		t.Fatalf("unexpected structure %+v err %v", structure, err)
	}
	grants, err := db.ListOwnerGrants(ctx, "user-roundtrip")
	if err != nil || len(grants) != 1 || grants[0].Role != "write" {
		t.Fatalf("unexpected grants %+v err %v", grants, err)
	}
}

func TestCreateAccountRejectsDuplicateEmail(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	if err := db.CreateAccount(ctx, sampleAccount("user-dup-a", "dup@example.com")); err != nil {
		t.Fatalf("first account: %v", err)
	}
	err := db.CreateAccount(ctx, sampleAccount("user-dup-b", "dup@example.com"))
	if err != ErrEmailTaken {
		t.Fatalf("want ErrEmailTaken, got %v", err)
	}
	if _, err := db.GetUserByID(ctx, "user-dup-b"); err != ErrNotFound {
		t.Fatalf("rolled back account must not exist, got %v", err)
	}
}

func TestChangePasswordChecksBundleVersion(t *testing.T) {
	db := requireStore(t)
	ctx := context.Background()
	if err := db.CreateAccount(ctx, sampleAccount("user-pw", "pw@example.com")); err != nil {
		t.Fatal(err)
	}
	change := PasswordChange{UserID: "user-pw", ExpectedVersion: 2, AuthHash: "new", PwhashSalt: "bmV3", PwhashOps: 3, PwhashMem: 67108864, AmkPassword: "bmV3"}
	if err := db.ChangePassword(ctx, change); err != ErrConflict {
		t.Fatalf("stale version must conflict, got %v", err)
	}
	change.ExpectedVersion = 1
	if err := db.ChangePassword(ctx, change); err != nil {
		t.Fatalf("change password: %v", err)
	}
	user, _ := db.GetUserByID(ctx, "user-pw")
	bundle, _ := db.GetKeyBundle(ctx, "user-pw")
	if user.AuthHash != "new" || bundle.AmkPassword != "bmV3" || bundle.AmkRecovery != "Yg" {
		t.Fatalf("unexpected state %+v %+v", user, bundle)
	}
}

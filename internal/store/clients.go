package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SecretHash   string   `json:"secret_hash"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	// FirstParty clients are Neoworks' own apps, the only ones that may skip
	// the consent screen. Only the seed migration sets it.
	FirstParty  bool   `json:"first_party"`
	Public      bool   `json:"public"`
	Description string `json:"description"`
	// Verified means the owner proved control of every domain the app uses; the
	// api keeps it up to date.
	Verified     bool    `json:"verified"`
	ReviewStatus string  `json:"review_status"`
	ReviewReason *string `json:"review_reason"`
	// Logo is the logo asset; LogoHeld keeps it from users until the app is approved.
	Logo                *models.RecordID `json:"logo"`
	LogoHeld            bool             `json:"logo_held"`
	RateLimitMultiplier *float64         `json:"rate_limit_multiplier"`
	Owner               *models.RecordID `json:"owner"`
}

func (client *Client) IsConfidential() bool {
	return !client.Public && client.SecretHash != ""
}

// Suspended reports whether Neoworks suspended the client: it gets no new
// authorizations and no token refreshes.
func (client *Client) Suspended() bool {
	return client.ReviewStatus == "suspended"
}

// LogoAssetID is the asset of the logo users may see; empty without one, or
// while the logo waits for the app's approval.
func (client *Client) LogoAssetID() string {
	if client.Logo == nil {
		return ""
	}
	if client.LogoHeld && client.ReviewStatus != "approved" && !client.FirstParty {
		return ""
	}
	assetID, _ := client.Logo.ID.(string)
	return assetID
}

func (store *Store) GetClient(ctx context.Context, clientID string) (*Client, error) {
	return firstRow[Client](ctx, store, `
		SELECT record::id(id) AS id, name, secret_hash, redirect_uris, scopes, first_party, public,
			description, verified, review_status, review_reason, logo, logo_held, rate_limit_multiplier, owner
		FROM client WHERE id = $id LIMIT 1`,
		map[string]any{"id": recordID("client", clientID)})
}

// Owner is the person or organization behind an app or a scope.
type Owner struct {
	Handle      string `json:"handle"`
	Kind        string `json:"kind"`
	DisplayName string `json:"displayName"`
	// Verified is set by Neoworks for organizations it reviewed.
	Verified bool `json:"verified"`
}

type ownerRow struct {
	DisplayName *string    `json:"display_name"`
	VerifiedAt  *time.Time `json:"verified_at"`
	Handle      *string    `json:"handle"`
	FirstName   *string    `json:"first_name"`
	LastName    *string    `json:"last_name"`
}

// OwnerOf resolves an owner record (`user:<id>` or `organization:<handle>`).
func (store *Store) OwnerOf(ctx context.Context, record models.RecordID) (*Owner, error) {
	row, err := firstRow[ownerRow](ctx, store,
		"SELECT display_name, verified_at, handle, first_name, last_name FROM $owner",
		map[string]any{"owner": record})
	if err != nil {
		return nil, err
	}
	if record.Table == "organization" {
		handle, _ := record.ID.(string)
		return &Owner{Handle: handle, Kind: "organization", DisplayName: textOr(row.DisplayName, handle), Verified: row.VerifiedAt != nil}, nil
	}
	if row.Handle == nil {
		return nil, ErrNotFound
	}
	return &Owner{Handle: *row.Handle, Kind: "user", DisplayName: personName(row), Verified: false}, nil
}

func textOr(text *string, fallback string) string {
	if text == nil || *text == "" {
		return fallback
	}
	return *text
}

func personName(row *ownerRow) string {
	parts := []string{}
	if row.FirstName != nil && *row.FirstName != "" {
		parts = append(parts, *row.FirstName)
	}
	if row.LastName != nil && *row.LastName != "" {
		parts = append(parts, *row.LastName)
	}
	if len(parts) == 0 {
		return *row.Handle
	}
	return strings.Join(parts, " ")
}

// ClientOwner is who is behind the client, or nil for a client without an owner.
func (store *Store) ClientOwner(ctx context.Context, client *Client) (*Owner, error) {
	if client.Owner == nil {
		return nil, nil
	}
	owner, err := store.OwnerOf(ctx, *client.Owner)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return owner, err
}

type handleRow struct {
	ID           models.RecordID  `json:"id"`
	User         *models.RecordID `json:"user"`
	Organization *models.RecordID `json:"organization"`
}

// HandleOwners resolves handles (the scopes of collections) to their owners.
// Handles nobody holds are left out.
func (store *Store) HandleOwners(ctx context.Context, handles []string) (map[string]Owner, error) {
	records := make([]models.RecordID, 0, len(handles))
	for _, handle := range handles {
		records = append(records, recordID("handle", handle))
	}
	found, err := rows[handleRow](ctx, store, "SELECT id, user, organization FROM handle WHERE id IN $records",
		map[string]any{"records": records})
	if err != nil {
		return nil, err
	}
	owners := make(map[string]Owner, len(found))
	for _, row := range found {
		owner, err := store.handleOwner(ctx, row)
		if err != nil {
			return nil, err
		}
		if owner != nil {
			owners[owner.Handle] = *owner
		}
	}
	return owners, nil
}

func (store *Store) handleOwner(ctx context.Context, row handleRow) (*Owner, error) {
	record := row.User
	if row.Organization != nil {
		record = row.Organization
	}
	if record == nil {
		return nil, nil
	}
	owner, err := store.OwnerOf(ctx, *record)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return owner, err
}

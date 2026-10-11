package store

import "context"

type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SecretHash   string   `json:"secret_hash"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	// FirstParty clients are Neoworks' own apps, the only ones that may skip
	// the consent screen. Only the seed migration sets it.
	FirstParty bool `json:"first_party"`
	Public     bool `json:"public"`
}

func (client *Client) IsConfidential() bool {
	return !client.Public && client.SecretHash != ""
}

func (store *Store) GetClient(ctx context.Context, clientID string) (*Client, error) {
	return firstRow[Client](ctx, store, `
		SELECT record::id(id) AS id, name, secret_hash, redirect_uris, scopes,
			first_party, public
		FROM client WHERE id = $id LIMIT 1`,
		map[string]any{"id": recordID("client", clientID)})
}

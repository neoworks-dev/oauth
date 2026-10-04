package store

import (
	"context"
	"time"
)

type Install struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user"`
	ClientID  string     `json:"client"`
	EncPub    string     `json:"enc_pub"`
	SignPub   string     `json:"sign_pub"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

const installColumns = `record::id(id) AS id, record::id(user) AS user, record::id(client) AS client,
	enc_pub, sign_pub, name, created_at, revoked_at`

func (store *Store) GetInstall(ctx context.Context, installID string) (*Install, error) {
	return firstRow[Install](ctx, store,
		"SELECT "+installColumns+" FROM install WHERE id = $id LIMIT 1",
		map[string]any{"id": recordID("install", installID)})
}

// Certificate is a delegation certificate. Bytes and Signature are base64url.
type Certificate struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user"`
	InstallID string    `json:"install"`
	Bytes     string    `json:"bytes"`
	Signature string    `json:"signature"`
	CreatedAt time.Time `json:"created_at"`
}

// AccessGrant is the stored form of an access grant (contract section 5).
type AccessGrant struct {
	NodeID        string     `json:"node_id"`
	PrincipalType string     `json:"principal_type"`
	PrincipalID   string     `json:"principal_id"`
	Role          string     `json:"role"`
	Facets        []uint32   `json:"facets"`
	Epoch         uint32     `json:"epoch"`
	WrappedKeys   string     `json:"wrapped_keys"`
	GrantedByType string     `json:"granted_by_type"`
	GrantedByID   string     `json:"granted_by_id"`
	CertID        string     `json:"cert_id"`
	Signature     string     `json:"signature"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
}

const accessGrantColumns = `node_id, principal_type, principal_id, role, facets, epoch,
	wrapped_keys, granted_by_type, granted_by_id, cert_id, signature, created_at, revoked_at`

func accessGrantFields(grant AccessGrant) map[string]any {
	fields := map[string]any{
		"node_id":         grant.NodeID,
		"principal_type":  grant.PrincipalType,
		"principal_id":    grant.PrincipalID,
		"role":            grant.Role,
		"epoch":           grant.Epoch,
		"wrapped_keys":    grant.WrappedKeys,
		"granted_by_type": grant.GrantedByType,
		"granted_by_id":   grant.GrantedByID,
		"signature":       grant.Signature,
		"created_at":      grant.CreatedAt,
	}
	if grant.Facets != nil {
		fields["facets"] = grant.Facets
	}
	if grant.CertID != "" {
		fields["cert_id"] = grant.CertID
	}
	return fields
}

func accessLogFields(grant AccessGrant, action string) map[string]any {
	fields := accessGrantFields(grant)
	fields["action"] = action
	return fields
}

// InstallConsent is everything a consent writes: the install, its delegation
// certificate and the install grants.
type InstallConsent struct {
	Install     Install
	Certificate Certificate
	Grants      []AccessGrant
}

// SaveInstallConsent stores an install, its certificate and grants in one
// transaction. Earlier active grants of the install on the same nodes are
// replaced, and every grant is appended to access_log.
func (store *Store) SaveInstallConsent(ctx context.Context, consent InstallConsent) error {
	grantRows := make([]map[string]any, 0, len(consent.Grants))
	logRows := make([]map[string]any, 0, len(consent.Grants))
	for _, grant := range consent.Grants {
		grantRows = append(grantRows, accessGrantFields(grant))
		logRows = append(logRows, accessLogFields(grant, "grant"))
	}
	return execute(ctx, store, `
		BEGIN TRANSACTION;
		UPSERT $install_id SET user = $user, client = $client, enc_pub = $enc_pub,
			sign_pub = $sign_pub, name = $install_name;
		CREATE $certificate_id SET user = $user, install = $install_id,
			bytes = $certificate_bytes, signature = $certificate_signature;
		DELETE access_grant WHERE principal_type = 'install' AND principal_id = $install_key
			AND node_id IN $node_ids;
		INSERT INTO access_grant $grant_rows;
		INSERT INTO access_log $log_rows;
		COMMIT TRANSACTION;`,
		map[string]any{
			"install_id":            recordID("install", consent.Install.ID),
			"install_key":           consent.Install.ID,
			"user":                  recordID("user", consent.Install.UserID),
			"client":                recordID("client", consent.Install.ClientID),
			"enc_pub":               consent.Install.EncPub,
			"sign_pub":              consent.Install.SignPub,
			"install_name":          consent.Install.Name,
			"certificate_id":        recordID("certificate", consent.Certificate.ID),
			"certificate_bytes":     consent.Certificate.Bytes,
			"certificate_signature": consent.Certificate.Signature,
			"node_ids":              grantNodeIDs(consent.Grants),
			"grant_rows":            grantRows,
			"log_rows":              logRows,
		})
}

func grantNodeIDs(grants []AccessGrant) []string {
	nodeIDs := make([]string, 0, len(grants))
	for _, grant := range grants {
		nodeIDs = append(nodeIDs, grant.NodeID)
	}
	return nodeIDs
}

// InstallGrantBundle is the neoworks_grant payload source for one install.
type InstallGrantBundle struct {
	Certificate Certificate
	Grants      []AccessGrant
}

// GetInstallGrantBundle returns the install's newest certificate and its active grants.
func (store *Store) GetInstallGrantBundle(ctx context.Context, installID string) (*InstallGrantBundle, error) {
	certificate, err := firstRow[Certificate](ctx, store, `
		SELECT record::id(id) AS id, record::id(user) AS user, record::id(install) AS install,
			bytes, signature, created_at
		FROM certificate WHERE install = $install ORDER BY created_at DESC LIMIT 1`,
		map[string]any{"install": recordID("install", installID)})
	if err != nil {
		return nil, err
	}
	grants, err := rows[AccessGrant](ctx, store, `
		SELECT `+accessGrantColumns+` FROM access_grant
		WHERE principal_type = 'install' AND principal_id = $install_key AND revoked_at = NONE`,
		map[string]any{"install_key": installID})
	if err != nil {
		return nil, err
	}
	return &InstallGrantBundle{Certificate: *certificate, Grants: grants}, nil
}

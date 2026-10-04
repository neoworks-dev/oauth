package flowtest

import (
	"testing"
	"time"

	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/wire"
)

// consentWithCertificate is consentFor with a certificate of the given lifetime.
func consentWithCertificate(system *system, account *testsupport.Account, install testsupport.Install, challengeID string, scopes []string, lifetime time.Duration) map[string]any {
	body := consentFor(account, install, system.clientID, challengeID, scopes, map[string]string{"calendar": "write"})
	certificate := account.Certificate(testsupport.CertificateParams{
		InstallID: install.ID, ClientID: system.clientID,
		InstallEncPub: wire.EncodeBase64URL(install.EncPub[:]), InstallSignPub: wire.EncodeBase64URL(install.SignPub),
		Scopes: scopes, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(lifetime),
	})
	body["certificate"], body["certificateSignature"] = certificate.Bytes, certificate.Signature
	body["grants"] = []map[string]any{
		account.Grant(account.RootIDs["calendar"], "install", install.ID, "write", 1, nil, install.EncPub, certificate.CertID),
	}
	return body
}

func TestCertificatesLiveAtMostAboutThirtyDays(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("lifetime")
	install := testsupport.NewInstall()
	_, challenge := pkce()
	scopes := []string{"calendar:read", "calendar:write"}

	longLived := system.authorize(system.authorizeParams(install, challenge, "calendar:read calendar:write"))
	body := consentWithCertificate(system, account, install, challengeID(longLived), scopes, 90*24*time.Hour)
	if response := system.browser.Do("POST", "/vault/consent", body, nil); response.Status != 400 {
		t.Fatalf("a 90-day certificate: status %d, want 400", response.Status)
	}
}

func TestShareScopeIsGrantedOnlyWhenApprovedWithAccess(t *testing.T) {
	system := newSystem(t)
	account := system.freshAccount("share")
	install := testsupport.NewInstall()
	_, challenge := pkce()

	withShare := []string{"calendar:read", "calendar:write", "calendar:share"}
	location := system.authorize(system.authorizeParams(install, challenge, "calendar:read calendar:write calendar:share"))
	body := consentWithCertificate(system, account, install, challengeID(location), withShare, 30*24*time.Hour)
	response := system.browser.Do("POST", "/vault/consent", body, nil)
	if response.Status != 200 {
		t.Fatalf("consent with the share scope: %d %s", response.Status, response.Raw)
	}
	account.CommitGrants()

	other := testsupport.NewInstall()
	shareOnly := system.authorize(system.authorizeParams(other, challenge, "calendar:share"))
	bare := map[string]any{"loginChallenge": challengeID(shareOnly), "scopes": []string{"calendar:share"}}
	if rejected := system.browser.Do("POST", "/vault/consent", bare, nil); rejected.Status != 400 {
		t.Fatalf("share without read or write: status %d, want 400", rejected.Status)
	}
}

// shareRootWith stores a whole-node user grant from owner to recipient.
func shareRootWith(t *testing.T, owner, recipient *testsupport.Account, role string) string {
	t.Helper()
	rootID := owner.RootIDs["calendar"]
	err := testSurreal.Exec(`CREATE access_grant SET node_id = $node, principal_type = 'user', principal_id = $recipient,
		role = $role, epoch = 1, wrapped_keys = 'sealed', granted_by_type = 'user', granted_by_id = $owner,
		signature = 'signature', log_index = 1`,
		map[string]any{"node": rootID, "recipient": recipient.UserID, "role": role, "owner": owner.UserID})
	if err != nil {
		t.Fatalf("share root: %v", err)
	}
	recipient.LogHeads[rootID] = owner.LogHeads[rootID]
	return rootID
}

func consentOnSharedRoot(system *system, recipient *testsupport.Account, install testsupport.Install, challengeID, rootID, role string, scopes []string) map[string]any {
	certificate := recipient.Certificate(testsupport.CertificateParams{
		InstallID: install.ID, ClientID: system.clientID,
		InstallEncPub: wire.EncodeBase64URL(install.EncPub[:]), InstallSignPub: wire.EncodeBase64URL(install.SignPub),
		Scopes: scopes, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})
	return map[string]any{
		"loginChallenge": challengeID, "scopes": scopes,
		"certificate": certificate.Bytes, "certificateSignature": certificate.Signature,
		"grants": []map[string]any{recipient.Grant(rootID, "install", install.ID, role, 1, nil, install.EncPub, certificate.CertID)},
	}
}

func TestConsentPassesASharedNodeOnUpToTheUsersOwnRole(t *testing.T) {
	system := newSystem(t)
	owner := system.freshAccount("owner")
	recipient := system.freshAccount("recipient")
	rootID := shareRootWith(t, owner, recipient, "read")
	_, challenge := pkce()
	scopes := []string{"calendar:read", "calendar:write"}

	cases := map[string]struct {
		role   string
		status int
	}{
		"read within the user's read": {"read", 200},
		"write above the user's read": {"write", 400},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			install := testsupport.NewInstall()
			location := system.authorize(system.authorizeParams(install, challenge, "calendar:read calendar:write"))
			body := consentOnSharedRoot(system, recipient, install, challengeID(location), rootID, testCase.role, scopes)
			response := system.browser.Do("POST", "/vault/consent", body, nil)
			if response.Status != testCase.status {
				t.Fatalf("status %d (%s), want %d", response.Status, response.Raw, testCase.status)
			}
			recipient.LogHeads[rootID] = owner.LogHeads[rootID]
		})
	}
}

func TestConsentRefusesANodeNobodySharedWithTheUser(t *testing.T) {
	system := newSystem(t)
	owner := system.freshAccount("private")
	recipient := system.freshAccount("stranger")
	rootID := owner.RootIDs["calendar"]
	recipient.LogHeads[rootID] = owner.LogHeads[rootID]
	install := testsupport.NewInstall()
	_, challenge := pkce()
	location := system.authorize(system.authorizeParams(install, challenge, "calendar:read"))
	body := consentOnSharedRoot(system, recipient, install, challengeID(location), rootID, "read", []string{"calendar:read"})
	if response := system.browser.Do("POST", "/vault/consent", body, nil); response.Status != 400 {
		t.Fatalf("status %d, want 400", response.Status)
	}
}


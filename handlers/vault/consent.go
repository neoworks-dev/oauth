package vault

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/ids"
	"github.com/neoworks/oauth/internal/scopes"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/wire"
)

const (
	authCodeTTL         = 5 * time.Minute
	certificateSkew     = 10 * time.Minute
	certificateMaxLife  = 400 * 24 * time.Hour
	maxGrantsPerConsent = 500
)

// certificateDocument is the JSON inside a delegation certificate. The server
// parses it only after verifying the signature over its exact bytes.
type certificateDocument struct {
	Version        int      `json:"v"`
	CertID         string   `json:"certId"`
	UserID         string   `json:"userId"`
	InstallID      string   `json:"installId"`
	ClientID       string   `json:"clientId"`
	InstallEncPub  string   `json:"installEncPub"`
	InstallSignPub string   `json:"installSignPub"`
	Scopes         []string `json:"scopes"`
	IssuedAt       string   `json:"issuedAt"`
	ExpiresAt      string   `json:"expiresAt"`
}

type consentRequest struct {
	LoginChallenge       string         `json:"loginChallenge"`
	Scopes               []string       `json:"scopes"`
	Certificate          string         `json:"certificate"`
	CertificateSignature string         `json:"certificateSignature"`
	Grants               []grantPayload `json:"grants"`
}

// consentContext is the verified state a consent is checked against.
type consentContext struct {
	userID    string
	signPub   []byte
	challenge *cache.LoginChallenge
	approved  []string
	now       time.Time
}

func (server *Server) handleConsent(response http.ResponseWriter, request *http.Request) {
	var body consentRequest
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	consent, ok := server.consentContextFor(response, request, body)
	if !ok {
		return
	}
	if consent.challenge.Install != nil {
		if !server.storeInstallConsent(response, request, consent, body) {
			return
		}
	}
	server.issueAuthorizationCode(response, request, consent)
}

func (server *Server) consentContextFor(response http.ResponseWriter, request *http.Request, body consentRequest) (consentContext, bool) {
	userID := sessionFrom(request).Session.UserID
	challenge, err := server.state.GetLoginChallenge(request.Context(), body.LoginChallenge)
	if err != nil {
		writeError(response, http.StatusNotFound, "challenge_not_found")
		return consentContext{}, false
	}
	if !scopes.Subset(challenge.Scopes, body.Scopes) {
		writeError(response, http.StatusBadRequest, "scope_not_requested")
		return consentContext{}, false
	}
	if challenge.Install == nil && scopes.WantsCollections(body.Scopes) {
		writeError(response, http.StatusBadRequest, "install_required")
		return consentContext{}, false
	}
	bundle, err := server.store.GetKeyBundle(request.Context(), userID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return consentContext{}, false
	}
	signPub, err := decodeSized(bundle.SignPub, publicKeyBytes)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return consentContext{}, false
	}
	return consentContext{userID: userID, signPub: signPub, challenge: challenge, approved: body.Scopes, now: time.Now().UTC()}, true
}

// storeInstallConsent verifies the certificate and grants and writes them.
// It writes the HTTP error itself and reports success.
func (server *Server) storeInstallConsent(response http.ResponseWriter, request *http.Request, consent consentContext, body consentRequest) bool {
	certificate, err := verifiedCertificate(consent, body)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_certificate")
		return false
	}
	if !server.installAvailable(response, request, consent) {
		return false
	}
	grants, err := server.verifiedInstallGrants(request, consent, certificate, body.Grants)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_grants")
		return false
	}
	err = server.store.SaveInstallConsent(request.Context(), store.InstallConsent{
		Install:     installRecord(consent),
		Certificate: store.Certificate{ID: certificate.CertID, UserID: consent.userID, InstallID: certificate.InstallID, Bytes: body.Certificate, Signature: body.CertificateSignature},
		Grants:      grants,
	})
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return false
	}
	return true
}

func installRecord(consent consentContext) store.Install {
	install := consent.challenge.Install
	return store.Install{
		ID: install.ID, UserID: consent.userID, ClientID: consent.challenge.ClientID,
		EncPub: install.EncPub, SignPub: install.SignPub, Name: install.Name, CreatedAt: consent.now,
	}
}

// installAvailable refuses to reuse an install id that belongs to someone else,
// to another app, or that was revoked.
func (server *Server) installAvailable(response http.ResponseWriter, request *http.Request, consent consentContext) bool {
	install := consent.challenge.Install
	existing, err := server.store.GetInstall(request.Context(), install.ID)
	if err == store.ErrNotFound {
		return true
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return false
	}
	sameInstall := existing.UserID == consent.userID && existing.ClientID == consent.challenge.ClientID &&
		existing.EncPub == install.EncPub && existing.SignPub == install.SignPub
	if !sameInstall || existing.RevokedAt != nil {
		writeError(response, http.StatusConflict, "install_unavailable")
		return false
	}
	return true
}

// verifiedCertificate checks the certificate signature and that its contents
// match the request the user approved.
func verifiedCertificate(consent consentContext, body consentRequest) (*certificateDocument, error) {
	certificateBytes, err := decodeBounded(body.Certificate, maxBlobTextSize)
	if err != nil {
		return nil, err
	}
	signature, err := decodeSized(body.CertificateSignature, signatureBytes)
	if err != nil {
		return nil, err
	}
	if !wire.Verify(consent.signPub, wire.DelegationMessage(certificateBytes), signature) {
		return nil, errInvalidPayload
	}
	var document certificateDocument
	if err := json.Unmarshal(certificateBytes, &document); err != nil {
		return nil, errInvalidPayload
	}
	if err := checkCertificateFields(consent, document); err != nil {
		return nil, err
	}
	return &document, nil
}

func checkCertificateFields(consent consentContext, document certificateDocument) error {
	install := consent.challenge.Install
	matchesRequest := document.Version == 1 && document.UserID == consent.userID &&
		document.InstallID == install.ID && document.ClientID == consent.challenge.ClientID &&
		document.InstallEncPub == install.EncPub && document.InstallSignPub == install.SignPub &&
		sameScopes(document.Scopes, consent.approved)
	if !matchesRequest || !validCertificateID(document.CertID) {
		return errInvalidPayload
	}
	return checkCertificateTimes(consent.now, document)
}

func sameScopes(left, right []string) bool {
	leftSorted := slices.Sorted(slices.Values(left))
	rightSorted := slices.Sorted(slices.Values(right))
	return slices.Equal(leftSorted, rightSorted)
}

func checkCertificateTimes(now time.Time, document certificateDocument) error {
	issuedAt, err := time.Parse(time.RFC3339, document.IssuedAt)
	if err != nil {
		return errInvalidPayload
	}
	expiresAt, err := time.Parse(time.RFC3339, document.ExpiresAt)
	if err != nil {
		return errInvalidPayload
	}
	issuedNow := issuedAt.After(now.Add(-certificateSkew)) && issuedAt.Before(now.Add(certificateSkew))
	if !issuedNow || !expiresAt.After(now) || expiresAt.Sub(issuedAt) > certificateMaxLife {
		return errInvalidPayload
	}
	return nil
}

// verifiedInstallGrants checks every install grant against the user's nodes,
// the approved scopes and the user's signature.
func (server *Server) verifiedInstallGrants(request *http.Request, consent consentContext, certificate *certificateDocument, grants []grantPayload) ([]store.AccessGrant, error) {
	roles := scopes.CollectionRoles(consent.approved)
	if len(grants) > maxGrantsPerConsent || (len(roles) > 0 && len(grants) == 0) {
		return nil, errInvalidPayload
	}
	nodes, err := server.grantedNodes(request, grants)
	if err != nil {
		return nil, err
	}
	stored := make([]store.AccessGrant, 0, len(grants))
	seenNodes := map[string]bool{}
	coveredCollections := map[string]bool{}
	for _, grant := range grants {
		node, found := nodes[grant.NodeID]
		if !found || seenNodes[grant.NodeID] {
			return nil, errInvalidPayload
		}
		if err := checkInstallGrant(consent, certificate, roles, node, grant); err != nil {
			return nil, err
		}
		seenNodes[grant.NodeID] = true
		coveredCollections[node.Collection] = true
		stored = append(stored, grant.toStored(consent.now))
	}
	for collection := range roles {
		if !coveredCollections[collection] {
			return nil, errInvalidPayload
		}
	}
	return stored, nil
}

func (server *Server) grantedNodes(request *http.Request, grants []grantPayload) (map[string]store.NodeOwnership, error) {
	nodeIDs := make([]string, 0, len(grants))
	for _, grant := range grants {
		nodeIDs = append(nodeIDs, grant.NodeID)
	}
	found, err := server.store.GetNodeOwnerships(request.Context(), nodeIDs)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]store.NodeOwnership, len(found))
	for _, node := range found {
		byID[node.ID] = node
	}
	return byID, nil
}

func checkInstallGrant(consent consentContext, certificate *certificateDocument, roles map[string]string, node store.NodeOwnership, grant grantPayload) error {
	install := consent.challenge.Install
	targetsInstall := grant.PrincipalType == "install" && grant.PrincipalID == install.ID
	grantedByUser := grant.GrantedByType == "user" && grant.GrantedByID == consent.userID
	certified := grant.CertID != nil && *grant.CertID == certificate.CertID
	if !targetsInstall || !grantedByUser || !certified {
		return errInvalidPayload
	}
	if node.OwnerID != consent.userID || node.Epoch != grant.Epoch || !roleAllowed(roles[node.Collection], grant.Role) {
		return errInvalidPayload
	}
	return verifyGrantSignature(grant, consent.signPub)
}

// roleAllowed reports whether a grant role fits within the scope's role.
func roleAllowed(scopeRole, grantRole string) bool {
	if scopeRole == "write" {
		return grantRole == "read" || grantRole == "write"
	}
	return scopeRole == "read" && grantRole == "read"
}

func (server *Server) issueAuthorizationCode(response http.ResponseWriter, request *http.Request, consent consentContext) {
	ctx := request.Context()
	challenge, err := server.state.TakeLoginChallenge(ctx, consent.challenge.ID)
	if err != nil {
		writeError(response, http.StatusConflict, "challenge_used")
		return
	}
	code := newAuthorizationCode()
	authCode := cache.AuthCode{
		Code: code, ClientID: challenge.ClientID, UserID: consent.userID, RedirectURI: challenge.RedirectURI,
		Scopes: consent.approved, CodeChallenge: challenge.CodeChallenge, CodeChallengeMethod: challenge.CodeChallengeMethod,
		ExpiresAt: time.Now().Add(authCodeTTL),
	}
	if challenge.Install != nil {
		authCode.InstallID = challenge.Install.ID
	}
	if err := server.state.SaveAuthCode(ctx, authCode); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	redirect, err := redirectWithCode(challenge.RedirectURI, code, challenge.State)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"redirect": redirect})
}

func newAuthorizationCode() string {
	code := make([]byte, 32)
	_, _ = rand.Read(code)
	return wire.EncodeBase64URL(code)
}

// validCertificateID reports whether a certificate id is a lowercase UUIDv4.
func validCertificateID(certID string) bool {
	return ids.IsLowercaseUUIDv4(certID)
}

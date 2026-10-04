package vault

import (
	"net/http"
	"strings"
	"time"

	"github.com/neoworks/oauth/internal/ids"
	"github.com/neoworks/oauth/internal/scopes"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/wire"
	"golang.org/x/crypto/bcrypt"
)

const maxNameLength = 100

func (server *Server) handleSignupSendCode(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := readJSON(request, &body); err != nil || normalizeEmail(body.Email) == "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	email := normalizeEmail(body.Email)
	if server.codeSendLimited(request, "signup", email) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if server.findUser(request, email) != nil {
		writeError(response, http.StatusConflict, "email_taken")
		return
	}
	code, err := server.issueCode(request.Context(), "signup", email, "Verify your email for Neoworks")
	if err != nil {
		writeError(response, http.StatusInternalServerError, "send_failed")
		return
	}
	server.codeResponse(response, code)
}

func (server *Server) handleSignupVerifyCode(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	email := normalizeEmail(body.Email)
	result := server.checkCode(request, "signup", email, body.Code)
	if result != "ok" {
		codeFailureResponse(response, result)
		return
	}
	if err := server.state.MarkEmailVerified(request.Context(), email); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"verified": true})
}

// signupRequest is everything the browser generates for a new account.
type signupRequest struct {
	Email     string         `json:"email"`
	FirstName string         `json:"firstName"`
	LastName  string         `json:"lastName"`
	UserID    string         `json:"userId"`
	AuthKey   string         `json:"authKey"`
	Pwhash    pwhashParams   `json:"pwhash"`
	Bundle    bundlePayload  `json:"bundle"`
	Nodes     []nodePayload  `json:"nodes"`
	Grants    []grantPayload `json:"grants"`
	Device    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"device"`
	Escrow *struct {
		SealedAmk string `json:"sealedAmk"`
	} `json:"escrow"`
}

func (server *Server) handleSignup(response http.ResponseWriter, request *http.Request) {
	var body signupRequest
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	body.Email = normalizeEmail(body.Email)
	account, err := buildAccount(body, time.Now().UTC())
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx := request.Context()
	verified, err := server.state.ConsumeEmailVerified(ctx, account.Email)
	if err != nil || !verified {
		writeError(response, http.StatusForbidden, "email_not_verified")
		return
	}
	if !server.enrollEscrow(response, request, body) {
		return
	}
	account.EscrowEnabled = body.Escrow != nil
	err = server.store.CreateAccount(ctx, account)
	if err == store.ErrEmailTaken {
		writeError(response, http.StatusConflict, "email_taken")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if err := server.startSession(response, request, account.UserID, account.Device.ID); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"userId": account.UserID})
}

// buildAccount validates a signup request and converts it to the stored form.
func buildAccount(body signupRequest, now time.Time) (store.NewAccount, error) {
	var account store.NewAccount
	if !ids.IsLowercaseUUIDv4(body.UserID) || !ids.IsLowercaseUUIDv4(body.Device.ID) {
		return account, errInvalidPayload
	}
	if body.Email == "" || !strings.Contains(body.Email, "@") || len(body.Email) > 254 {
		return account, errInvalidPayload
	}
	authKey, valid := parseAuthKey(body.AuthKey)
	if !valid || len(body.FirstName) > maxNameLength || len(body.LastName) > maxNameLength {
		return account, errInvalidPayload
	}
	if err := checkPwhashParams(body.Pwhash); err != nil {
		return account, err
	}
	signPub, err := checkInitialBundle(body)
	if err != nil {
		return account, err
	}
	nodes, grants, err := buildRootTree(body, signPub, now)
	if err != nil {
		return account, err
	}
	authHash, err := bcrypt.GenerateFromPassword([]byte(authKey), bcrypt.DefaultCost)
	if err != nil {
		return account, err
	}
	return store.NewAccount{
		UserID:    body.UserID,
		Email:     body.Email,
		FirstName: strings.TrimSpace(body.FirstName),
		LastName:  strings.TrimSpace(body.LastName),
		AuthHash:  string(authHash),
		Bundle:    storedBundle(body.UserID, body.Bundle, body.Pwhash),
		Device:    store.Device{ID: body.Device.ID, Name: cleanDeviceName(body.Device.Name), Kind: "browser"},
		Nodes:     nodes,
		Grants:    grants,
	}, nil
}

// checkPwhashParams requires the single parameter set of the contract and a
// 16 byte salt.
func checkPwhashParams(params pwhashParams) error {
	if params.Ops != pwhashOps || params.Mem != pwhashMem {
		return errInvalidPayload
	}
	_, err := decodeSized(params.Salt, pwhashSaltBytes)
	return err
}

func checkInitialBundle(body signupRequest) ([]byte, error) {
	if body.Bundle.Version != 1 {
		return nil, errInvalidPayload
	}
	if err := checkOpaqueBundleFields(body.Bundle); err != nil {
		return nil, err
	}
	return verifiedIdentity(body.UserID, body.Bundle)
}

func storedBundle(userID string, bundle bundlePayload, params pwhashParams) store.KeyBundle {
	return store.KeyBundle{
		UserID:          userID,
		Version:         bundle.Version,
		PwhashSalt:      params.Salt,
		PwhashOps:       params.Ops,
		PwhashMem:       params.Mem,
		AmkPassword:     bundle.AmkPassword,
		AmkRecovery:     bundle.AmkRecovery,
		IdentityPrivate: bundle.IdentityPrivate,
		EncPub:          bundle.EncPub,
		SignPub:         bundle.SignPub,
		SelfSig:         bundle.SelfSig,
	}
}

// buildRootTree checks the root nodes and the owner's grant on each, which is
// entry 0 of the root's access log.
func buildRootTree(body signupRequest, signPub []byte, now time.Time) ([]store.Node, []store.AccessGrant, error) {
	if len(body.Nodes) != len(scopes.Collections) || len(body.Grants) != len(scopes.Collections) {
		return nil, nil, errInvalidPayload
	}
	nodes := make([]store.Node, 0, len(body.Nodes))
	grants := make([]store.AccessGrant, 0, len(body.Grants))
	seenCollections := map[string]bool{}
	for index, node := range body.Nodes {
		stored, err := rootNode(body.UserID, node, uint64(index+1), now)
		if err != nil || seenCollections[node.Collection] {
			return nil, nil, errInvalidPayload
		}
		seenCollections[node.Collection] = true
		grant, err := ownerGrant(body.UserID, stored, body.Grants, signPub, now)
		if err != nil {
			return nil, nil, err
		}
		nodes = append(nodes, stored)
		grants = append(grants, grant)
	}
	return nodes, grants, nil
}

func rootNode(userID string, node nodePayload, seq uint64, now time.Time) (store.Node, error) {
	if !ids.IsLowercaseUUIDv4(node.ID) || node.OwnerID != userID || node.Kind != "root" {
		return store.Node{}, errInvalidPayload
	}
	if node.ParentID != nil || node.WrappedKey != nil || node.Blob != nil || node.Deleted || node.BaseSeq != 0 {
		return store.Node{}, errInvalidPayload
	}
	if node.AuthorType != "user" || node.AuthorID != userID || node.CertID != nil {
		return store.Node{}, errInvalidPayload
	}
	if !isCollection(node.Collection) || node.Epoch == 0 {
		return store.Node{}, errInvalidPayload
	}
	if _, err := decodeSized(node.Signature, signatureBytes); err != nil {
		return store.Node{}, err
	}
	content, err := storedContent(node.Content)
	if err != nil {
		return store.Node{}, err
	}
	return store.Node{
		ID: node.ID, OwnerID: userID, Collection: node.Collection, Kind: "root", Epoch: node.Epoch,
		Content: content, Seq: seq, AuthorType: "user", AuthorID: userID, Signature: node.Signature,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func isCollection(name string) bool {
	for _, collection := range scopes.Collections {
		if collection == name {
			return true
		}
	}
	return false
}

func storedContent(content []facetPayload) ([]store.NodeFacet, error) {
	if len(content) == 0 || len(content) > 8 {
		return nil, errInvalidPayload
	}
	stored := make([]store.NodeFacet, 0, len(content))
	for _, facet := range content {
		if _, err := decodeBounded(facet.Ciphertext, maxBlobTextSize); err != nil {
			return nil, err
		}
		stored = append(stored, store.NodeFacet{Facet: facet.Facet, Ciphertext: facet.Ciphertext})
	}
	return stored, nil
}

func ownerGrant(userID string, node store.Node, grants []grantPayload, signPub []byte, now time.Time) (store.AccessGrant, error) {
	for _, grant := range grants {
		if grant.NodeID != node.ID {
			continue
		}
		return checkedOwnerGrant(userID, node, grant, signPub, now)
	}
	return store.AccessGrant{}, errInvalidPayload
}

func checkedOwnerGrant(userID string, node store.Node, grant grantPayload, signPub []byte, now time.Time) (store.AccessGrant, error) {
	isOwnerWrite := grant.PrincipalType == "user" && grant.PrincipalID == userID && grant.Role == "write"
	isSelfGranted := grant.GrantedByType == "user" && grant.GrantedByID == userID
	if !isOwnerWrite || !isSelfGranted || grant.Facets != nil || grant.CertID != nil || grant.Epoch != node.Epoch {
		return store.AccessGrant{}, errInvalidPayload
	}
	isGenesis := grant.LogIndex == 0 && grant.PrevHash == wire.EncodeBase64URL(wire.GenesisPrevHash)
	if !isGenesis {
		return store.AccessGrant{}, errInvalidPayload
	}
	return verifiedGrantEntry(grant, signPub, now)
}

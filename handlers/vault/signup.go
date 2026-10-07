package vault

import (
	"net/http"
	"strings"

	"github.com/neoworks/oauth/internal/ids"
	"github.com/neoworks/oauth/internal/store"
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
	Email     string        `json:"email"`
	FirstName string        `json:"firstName"`
	LastName  string        `json:"lastName"`
	UserID    string        `json:"userId"`
	AuthKey   string        `json:"authKey"`
	Pwhash    pwhashParams  `json:"pwhash"`
	Bundle    bundlePayload `json:"bundle"`
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
	account, err := buildAccount(body)
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
func buildAccount(body signupRequest) (store.NewAccount, error) {
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
	if _, err := checkInitialBundle(body); err != nil {
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
	if body.Bundle.Previous != nil {
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
		Previous:        storedPrevious(bundle.Previous),
	}
}

func storedPrevious(previous *previousIdentityPayload) *store.PreviousIdentity {
	if previous == nil {
		return nil
	}
	return &store.PreviousIdentity{IdentityPrivate: previous.IdentityPrivate, EncPub: previous.EncPub, SignPub: previous.SignPub}
}

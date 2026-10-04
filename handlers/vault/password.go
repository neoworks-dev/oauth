package vault

import (
	"net/http"

	"github.com/neoworks/oauth/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// newPasswordMaterial is the password-derived state a client replaces: the new
// authKey, its Argon2 parameters and the AMK wrapped by the new passwordKEK.
type newPasswordMaterial struct {
	NewAuthKey      string       `json:"newAuthKey"`
	Pwhash          pwhashParams `json:"pwhash"`
	AmkPassword     string       `json:"amkPassword"`
	ExpectedVersion uint32       `json:"expectedVersion"`
}

// passwordChange validates the material and converts it to a store change.
func (material newPasswordMaterial) passwordChange(userID string) (store.PasswordChange, error) {
	authKey, valid := parseAuthKey(material.NewAuthKey)
	if !valid {
		return store.PasswordChange{}, errInvalidPayload
	}
	if err := checkPwhashParams(material.Pwhash); err != nil {
		return store.PasswordChange{}, err
	}
	if _, err := decodeBounded(material.AmkPassword, maxBlobTextSize); err != nil {
		return store.PasswordChange{}, err
	}
	authHash, err := bcrypt.GenerateFromPassword([]byte(authKey), bcrypt.DefaultCost)
	if err != nil {
		return store.PasswordChange{}, err
	}
	return store.PasswordChange{
		UserID:          userID,
		ExpectedVersion: material.ExpectedVersion,
		AuthHash:        string(authHash),
		PwhashSalt:      material.Pwhash.Salt,
		PwhashOps:       material.Pwhash.Ops,
		PwhashMem:       material.Pwhash.Mem,
		AmkPassword:     material.AmkPassword,
	}, nil
}

func (server *Server) applyPasswordChange(response http.ResponseWriter, request *http.Request, change store.PasswordChange) {
	err := server.store.ChangePassword(request.Context(), change)
	if err == store.ErrConflict {
		writeError(response, http.StatusConflict, "bundle_version_conflict")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

// handleChangePassword replaces the password of a logged-in account. The
// current authKey is required so a hijacked session cannot lock the owner out.
func (server *Server) handleChangePassword(response http.ResponseWriter, request *http.Request) {
	var body struct {
		newPasswordMaterial
		CurrentAuthKey string `json:"currentAuthKey"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	userID := sessionFrom(request).Session.UserID
	if server.exceeded(request, "password_change:"+userID, loginMaxPerEmail, loginWindow) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	user, err := server.store.GetUserByID(request.Context(), userID)
	currentKey, validKey := parseAuthKey(body.CurrentAuthKey)
	if err != nil || !validKey || !verifyAuthKey(user, currentKey) {
		writeError(response, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	change, err := body.passwordChange(userID)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	server.applyPasswordChange(response, request, change)
}

func (server *Server) handleForgotSendCode(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := readJSON(request, &body); err != nil || normalizeEmail(body.Email) == "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	email := normalizeEmail(body.Email)
	if server.codeSendLimited(request, "reset", email) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if server.findUser(request, email) == nil {
		writeJSON(response, http.StatusOK, map[string]bool{"sent": true})
		return
	}
	code, err := server.issueCode(request.Context(), "reset", email, "Reset your Neoworks password")
	if err != nil {
		writeError(response, http.StatusInternalServerError, "send_failed")
		return
	}
	server.codeResponse(response, code)
}

// handleForgotVerifyCode checks the emailed code and, on success, releases what
// the client needs to unwrap the AMK with the recovery key, plus a one-use
// token for the reset.
func (server *Server) handleForgotVerifyCode(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	email := normalizeEmail(body.Email)
	if result := server.checkCode(request, "reset", email, body.Code); result != "ok" {
		codeFailureResponse(response, result)
		return
	}
	user := server.findUser(request, email)
	if user == nil {
		codeFailureResponse(response, "expired")
		return
	}
	server.releaseRecoveryMaterial(response, request, user, email)
}

func (server *Server) releaseRecoveryMaterial(response http.ResponseWriter, request *http.Request, user *store.User, email string) {
	bundle, err := server.store.GetKeyBundle(request.Context(), user.ID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	resetToken := newSessionToken()
	if err := server.state.SaveResetToken(request.Context(), resetToken, email); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"resetToken":      resetToken,
		"userId":          user.ID,
		"escrowEnabled":   user.EscrowEnabled,
		"bundle":          bundle,
		"wrapAadPurposes": []string{"password", "recovery"},
	})
}

func (server *Server) handleForgotReset(response http.ResponseWriter, request *http.Request) {
	var body struct {
		newPasswordMaterial
		ResetToken string `json:"resetToken"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	email, err := server.state.ConsumeResetToken(request.Context(), body.ResetToken)
	user := server.findUser(request, email)
	if err != nil || user == nil {
		writeError(response, http.StatusForbidden, "invalid_reset_token")
		return
	}
	change, err := body.passwordChange(user.ID)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	server.applyPasswordChange(response, request, change)
}

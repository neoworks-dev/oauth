package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/neoworks/oauth/internal/ids"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/wire"
	"golang.org/x/crypto/bcrypt"
)

const (
	pwhashOps        = 3
	pwhashMem        = 67108864
	pwhashSaltBytes  = 16
	authKeyBytes     = 32
	loginWindow      = 15 * time.Minute
	loginMaxPerEmail = 10
	loginMaxPerIP    = 60
	preloginMaxPerIP = 60
)

// pwhashParams are the per-account Argon2id parameters the client needs
// before it can derive authKey.
type pwhashParams struct {
	Salt string `json:"salt"`
	Ops  uint32 `json:"ops"`
	Mem  uint64 `json:"mem"`
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func clientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

// fakePwhashParams returns the parameters shown for an email with no account.
// They are a deterministic function of the email and a server secret, so
// repeated lookups agree with each other and with the shape of a real answer.
func (server *Server) fakePwhashParams(email string) pwhashParams {
	mac := hmac.New(sha256.New, server.config.PreloginSecret)
	mac.Write([]byte("prelogin-salt-v1:" + email))
	return pwhashParams{
		Salt: wire.EncodeBase64URL(mac.Sum(nil)[:pwhashSaltBytes]),
		Ops:  pwhashOps,
		Mem:  pwhashMem,
	}
}

func (server *Server) pwhashParamsFor(request *http.Request, email string) pwhashParams {
	user, err := server.store.GetUserByEmail(request.Context(), email)
	if err != nil {
		return server.fakePwhashParams(email)
	}
	bundle, err := server.store.GetKeyBundle(request.Context(), user.ID)
	if err != nil {
		return server.fakePwhashParams(email)
	}
	return pwhashParams{Salt: bundle.PwhashSalt, Ops: bundle.PwhashOps, Mem: bundle.PwhashMem}
}

func (server *Server) handlePrelogin(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := readJSON(request, &body); err != nil || normalizeEmail(body.Email) == "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if server.exceeded(request, "prelogin_ip:"+clientIP(request), preloginMaxPerIP, time.Minute) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return
	}
	writeJSON(response, http.StatusOK, server.pwhashParamsFor(request, normalizeEmail(body.Email)))
}

// exceeded counts one hit against a limit and reports whether it is now over.
// A broken counter fails open so Redis trouble cannot lock everyone out.
func (server *Server) exceeded(request *http.Request, key string, limit int64, window time.Duration) bool {
	count, err := server.state.CountWithin(request.Context(), key, window)
	return err == nil && count > limit
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// dummyAuthHash is compared against when the email is unknown, so unknown and
// known accounts cost the same time.
func dummyAuthHash() []byte {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("neoworks-dummy-auth-key"), bcrypt.DefaultCost)
	})
	return dummyHash
}

// parseAuthKey accepts exactly the canonical base64url form of 32 bytes and
// returns that canonical string.
func parseAuthKey(text string) (string, bool) {
	decoded, err := wire.DecodeBase64URL(text)
	if err != nil || len(decoded) != authKeyBytes {
		return "", false
	}
	canonical := wire.EncodeBase64URL(decoded)
	return canonical, canonical == text
}

// verifyAuthKey checks authKey against the stored hash. A missing user is
// verified against a dummy hash and always fails.
func verifyAuthKey(user *store.User, authKey string) bool {
	if user == nil {
		_ = bcrypt.CompareHashAndPassword(dummyAuthHash(), []byte(authKey))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(user.AuthHash), []byte(authKey)) == nil
}

type loginRequest struct {
	Email      string `json:"email"`
	AuthKey    string `json:"authKey"`
	DeviceID   string `json:"deviceId"`
	DeviceName string `json:"deviceName"`
}

func (server *Server) handleLogin(response http.ResponseWriter, request *http.Request) {
	body, user, ok := server.authenticatePassword(response, request)
	if !ok {
		return
	}
	server.completeLogin(response, request, user, body)
}

// authenticatePassword reads a loginRequest and verifies its authKey. On
// failure it has already written the error response.
func (server *Server) authenticatePassword(response http.ResponseWriter, request *http.Request) (loginRequest, *store.User, bool) {
	var body loginRequest
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return body, nil, false
	}
	email := normalizeEmail(body.Email)
	authKey, validKey := parseAuthKey(body.AuthKey)
	if email == "" || !validKey || !ids.IsLowercaseUUIDv4(body.DeviceID) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return body, nil, false
	}
	if server.loginRateLimited(request, email) {
		writeError(response, http.StatusTooManyRequests, "rate_limited")
		return body, nil, false
	}
	user := server.findUser(request, email)
	if !verifyAuthKey(user, authKey) {
		writeError(response, http.StatusUnauthorized, "invalid_credentials")
		return body, nil, false
	}
	return body, user, true
}

func (server *Server) loginRateLimited(request *http.Request, email string) bool {
	emailDigest := wire.EncodeBase64URL(wire.Hash([]byte(email)))
	if server.exceeded(request, "login_email:"+emailDigest, loginMaxPerEmail, loginWindow) {
		return true
	}
	return server.exceeded(request, "login_ip:"+clientIP(request), loginMaxPerIP, loginWindow)
}

func (server *Server) findUser(request *http.Request, email string) *store.User {
	user, err := server.store.GetUserByEmail(request.Context(), email)
	if err != nil {
		return nil
	}
	return user
}

func (server *Server) completeLogin(response http.ResponseWriter, request *http.Request, user *store.User, body loginRequest) {
	ctx := request.Context()
	err := server.store.RegisterDevice(ctx, user.ID, body.DeviceID, cleanDeviceName(body.DeviceName), "browser")
	if err == store.ErrRevoked {
		writeError(response, http.StatusForbidden, "device_revoked")
		return
	}
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	bundle, err := server.store.GetKeyBundle(ctx, user.ID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if err := server.startSession(response, request, user.ID, body.DeviceID); err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"userId": user.ID,
		"email":  user.Email,
		"name":   strings.TrimSpace(user.FirstName + " " + user.LastName),
		"bundle": bundle,
	})
}

func cleanDeviceName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Browser"
	}
	runes := []rune(name)
	if len(runes) > 80 {
		return string(runes[:80])
	}
	return name
}

package auth

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/email"
	"github.com/neoworks/auth/handlers/shared"
	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

//go:embed templates/signup.html
var signupTemplate string
var signupTmpl = template.Must(template.New("signup").Parse(signupTemplate))

//go:embed static/*.js
var staticFiles embed.FS

type SignupHandler struct {
	redis    *cache.RedisStore
	store    *database.SurrealStore
	issuer   *oauth.TokenIssuer
	mailer   email.Sender
	debug    bool
	loginURL string
}

func NewSignupHandler(redis *cache.RedisStore, store *database.SurrealStore, issuer *oauth.TokenIssuer, mailer email.Sender, debug bool, loginURL string) *SignupHandler {
	return &SignupHandler{
		redis:    redis,
		store:    store,
		issuer:   issuer,
		mailer:   mailer,
		debug:    debug,
		loginURL: loginURL,
	}
}

func (handler *SignupHandler) Register(r chi.Router) {
	r.Get("/auth/signup", handler.serveSignup)
	r.Post("/auth/signup", handler.handleSignup)
	r.Post("/auth/signup/send-code", handler.handleSendCode)
	r.Post("/auth/signup/verify-code", handler.handleVerifyCode)
	r.Get("/auth/static/libsodium.js", handler.serveStatic("libsodium.js"))
	r.Get("/auth/static/libsodium-wrappers.js", handler.serveStatic("libsodium-wrappers.js"))
	r.Get("/auth/static/recovery-words.js", handler.serveStatic("recovery-words.js"))
	r.Get("/auth/static/chat-ratchet.js", handler.serveStatic("chat-ratchet.js"))
	r.Get("/auth/static/scope-keys.js", handler.serveStatic("scope-keys.js"))
}

type signupData struct {
	LoginChallenge string
	AppName        string
	Error          string
}

// keyMaterial is the client-generated, AMK-wrapped key material submitted
// alongside the signup form. The AMK itself never leaves the browser —
// only these wrapped forms and the KDF params needed to re-derive the
// password-wrapping key on another device.
type keyMaterial struct {
	PasswordWrappedAMK string
	RecoveryWrappedAMK string
	Argon2Salt         string
	Argon2Time         int
	Argon2Memory       int
	Argon2Threads      int
	Argon2Keylen       int
	DevicePublicKey    string
	DeviceWrappedAMK   string
}

func (handler *SignupHandler) serveSignup(w http.ResponseWriter, r *http.Request) {
	loginChallenge := r.URL.Query().Get("login_challenge")
	if loginChallenge == "" {
		shared.RestartLogin(w, r, handler.loginURL)
		return
	}

	challenge, err := handler.redis.GetLoginChallenge(r.Context(), loginChallenge)
	if err != nil {
		shared.RestartLogin(w, r, handler.loginURL)
		return
	}

	ctx := r.Context()
	client, err := handler.store.GetClient(ctx, challenge.ClientID)
	if err != nil {
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}

	handler.render(w, signupData{LoginChallenge: loginChallenge, AppName: client.ID.ID.(string)})
}

func (handler *SignupHandler) handleSignup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	loginChallenge := r.FormValue("login_challenge")

	if firstName == "" || lastName == "" || email == "" || password == "" {
		handler.render(w, signupData{
			LoginChallenge: loginChallenge,
			Error:          "All fields are required",
		})
		return
	}

	if len(password) < 8 {
		handler.render(w, signupData{
			LoginChallenge: loginChallenge,
			Error:          "Password must be at least 8 characters",
		})
		return
	}

	// The email must have been proven via a verification code before any account
	// is persisted. The flag is consumed on success so it can't be reused.
	verified, err := handler.redis.IsEmailVerified(r.Context(), email)
	if err != nil {
		http.Error(w, "Failed to verify email", http.StatusInternalServerError)
		return
	}
	if !verified {
		handler.render(w, signupData{
			LoginChallenge: loginChallenge,
			Error:          "Please verify your email before creating your account",
		})
		return
	}

	keys, err := parseKeyMaterial(r)
	if err != nil {
		http.Error(w, "Account Master Key material is required — please enable JavaScript and try again", http.StatusBadRequest)
		return
	}

	user, err := handler.store.CreateUserWithKeys(r.Context(), &database.CreateUserWithKeysParams{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Password:  password,

		RecoveryWrappedAMK: keys.RecoveryWrappedAMK,
		PasswordWrappedAMK: keys.PasswordWrappedAMK,
		Argon2Salt:         keys.Argon2Salt,
		Argon2Time:         keys.Argon2Time,
		Argon2Memory:       keys.Argon2Memory,
		Argon2Threads:      keys.Argon2Threads,
		Argon2Keylen:       keys.Argon2Keylen,

		DevicePublicKey:  keys.DevicePublicKey,
		DeviceWrappedAMK: keys.DeviceWrappedAMK,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "already exists") {
			handler.render(w, signupData{
				LoginChallenge: loginChallenge,
				Error:          "An account with that email already exists",
			})
			return
		}
		http.Error(w, "Failed to create account", http.StatusInternalServerError)
		return
	}

	// Account exists now — burn the verification flag so it can't seed a second
	// signup with the same email.
	_ = handler.redis.ClearEmailVerified(r.Context(), email)

	// Sign the user in immediately so /account/security (and other oauth
	// pages on this origin) recognize this browser without a second login.
	// Adds to any existing device session so signups can stack accounts too.
	if err := shared.EstablishSSOSession(handler.redis, w, r, user.ID.ID.(string)); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	challenge, err := handler.redis.GetLoginChallenge(r.Context(), loginChallenge)
	if err != nil || challenge == nil {
		shared.RestartLogin(w, r, handler.loginURL)
		return
	}

	// User is created — continue into the consent flow
	r.Form.Set("login_challenge", loginChallenge)
	shared.HandleConsentRedirect(handler.redis, handler.store, handler.issuer, user, challenge, w, r)
}

// handleSendCode emails a fresh verification code for a prospective signup. It
// rejects emails that already have an account, since signup can't proceed for
// them anyway. Responds with JSON; the code is echoed back only in debug builds
// so local development and tests work without a real mailbox.
func (handler *SignupHandler) handleSendCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(body.Email)
	if email == "" {
		jsonError(w, "Email is required", http.StatusBadRequest)
		return
	}

	if _, err := handler.store.GetUserByEmail(r.Context(), email); err == nil {
		jsonError(w, "An account with that email already exists", http.StatusConflict)
		return
	}

	code := utils.GenerateNumericCode(6)
	if err := handler.redis.SaveVerificationCode(r.Context(), "signup", email, code); err != nil {
		jsonError(w, "Failed to issue code", http.StatusInternalServerError)
		return
	}

	if err := sendVerificationCode(r.Context(), handler.mailer, email, code); err != nil {
		slog.Error("signup: failed to send verification code", "email", email, "err", err)
		// In debug the code is echoed back in the response, so a broken SMTP
		// setup shouldn't block signup. In production it must.
		if !handler.debug {
			jsonError(w, "Failed to send code", http.StatusInternalServerError)
			return
		}
	}

	handler.respondCodeSent(w, code)
}

// handleVerifyCode checks a signup code and, on success, records that the email
// is verified so the final signup POST is allowed to create the account.
func (handler *SignupHandler) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(body.Email)
	code := strings.TrimSpace(body.Code)
	if email == "" || code == "" {
		jsonError(w, "Email and code are required", http.StatusBadRequest)
		return
	}

	stored, err := handler.redis.GetVerificationCode(r.Context(), "signup", email)
	if errors.Is(err, cache.ErrNotFound) {
		jsonError(w, "Code expired — please request a new one", http.StatusBadRequest)
		return
	}
	if err != nil {
		jsonError(w, "Failed to verify code", http.StatusInternalServerError)
		return
	}
	if stored != code {
		jsonError(w, "Incorrect code", http.StatusBadRequest)
		return
	}

	if err := handler.redis.MarkEmailVerified(r.Context(), email); err != nil {
		jsonError(w, "Failed to verify code", http.StatusInternalServerError)
		return
	}
	_ = handler.redis.DeleteVerificationCode(r.Context(), "signup", email)

	writeJSON(w, map[string]any{"verified": true})
}

// respondCodeSent reports success. In debug builds it also returns the code, so
// signing up works without a configured SMTP server.
func (handler *SignupHandler) respondCodeSent(w http.ResponseWriter, code string) {
	payload := map[string]any{"sent": true}
	if handler.debug {
		payload["code"] = code
	}
	writeJSON(w, payload)
}

// parseKeyMaterial reads the AMK-wrapped key material that signup.html's
// client-side script attaches to the form before submitting.
func parseKeyMaterial(r *http.Request) (*keyMaterial, error) {
	passwordWrappedAMK := r.FormValue("password_wrapped_amk")
	recoveryWrappedAMK := r.FormValue("recovery_wrapped_amk")
	argon2Salt := r.FormValue("argon2_salt")
	devicePublicKey := r.FormValue("device_public_key")
	deviceWrappedAMK := r.FormValue("device_wrapped_amk")

	if passwordWrappedAMK == "" || recoveryWrappedAMK == "" || argon2Salt == "" ||
		devicePublicKey == "" || deviceWrappedAMK == "" {
		return nil, fmt.Errorf("missing key material")
	}

	argon2Time, err := parsePositiveInt(r.FormValue("argon2_time"))
	if err != nil {
		return nil, fmt.Errorf("argon2_time: %w", err)
	}
	argon2Memory, err := parsePositiveInt(r.FormValue("argon2_memory"))
	if err != nil {
		return nil, fmt.Errorf("argon2_memory: %w", err)
	}
	argon2Threads, err := parsePositiveInt(r.FormValue("argon2_threads"))
	if err != nil {
		return nil, fmt.Errorf("argon2_threads: %w", err)
	}
	argon2Keylen, err := parsePositiveInt(r.FormValue("argon2_keylen"))
	if err != nil {
		return nil, fmt.Errorf("argon2_keylen: %w", err)
	}

	return &keyMaterial{
		PasswordWrappedAMK: passwordWrappedAMK,
		RecoveryWrappedAMK: recoveryWrappedAMK,
		Argon2Salt:         argon2Salt,
		Argon2Time:         argon2Time,
		Argon2Memory:       argon2Memory,
		Argon2Threads:      argon2Threads,
		Argon2Keylen:       argon2Keylen,
		DevicePublicKey:    devicePublicKey,
		DeviceWrappedAMK:   deviceWrappedAMK,
	}, nil
}

func parsePositiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid value %q", s)
	}
	return n, nil
}

func (handler *SignupHandler) render(w http.ResponseWriter, data signupData) {
	var buf bytes.Buffer
	if err := signupTmpl.Execute(&buf, data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// serveStatic serves a vendored, self-hosted static asset (e.g. the libsodium
// build used for client-side AMK generation). Self-hosted rather than
// loaded from a CDN, since a compromised CDN could exfiltrate users' AMKs.
func (handler *SignupHandler) serveStatic(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("static/" + filename)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(data)
	}
}

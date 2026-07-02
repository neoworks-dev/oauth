package auth

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/email"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

//go:embed templates/forgot.html
var forgotTemplate string
var forgotTmpl = template.Must(template.New("forgot").Parse(forgotTemplate))

//go:embed templates/reset.html
var resetTemplate string
var resetTmpl = template.Must(template.New("reset").Parse(resetTemplate))

// RecoveryHandler drives the forgot-password flow. Because the account master
// key is only ever wrapped client-side, the server can't reset a password on its
// own: the user must supply their recovery phrase so the browser can unwrap the
// AMK and re-wrap it under a new password. The emailed code only proves control
// of the email address and gates release of the recovery-wrapped AMK blob.
type RecoveryHandler struct {
	redis  *cache.RedisStore
	store  *database.SurrealStore
	mailer email.Sender
	debug  bool
}

func NewRecoveryHandler(redis *cache.RedisStore, store *database.SurrealStore, mailer email.Sender, debug bool) *RecoveryHandler {
	return &RecoveryHandler{redis: redis, store: store, mailer: mailer, debug: debug}
}

func (handler *RecoveryHandler) Register(r chi.Router) {
	r.Get("/auth/forgot", handler.serveForgot)
	r.Post("/auth/forgot", handler.handleForgot)
	r.Get("/auth/reset", handler.serveReset)
	r.Post("/auth/reset/verify-code", handler.handleVerifyResetCode)
	r.Post("/auth/reset", handler.handleReset)
}

type forgotData struct {
	LoginChallenge string
}

type resetData struct {
	LoginChallenge string
	Email          string
}

func (handler *RecoveryHandler) serveForgot(w http.ResponseWriter, r *http.Request) {
	render(w, forgotTmpl, forgotData{LoginChallenge: r.URL.Query().Get("login_challenge")})
}

// handleForgot issues a reset code if the email has an account, then always
// redirects to the reset page. The response is identical whether or not the
// account exists, so this endpoint never reveals which emails are registered.
func (handler *RecoveryHandler) handleForgot(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	loginChallenge := r.FormValue("login_challenge")
	if email == "" {
		render(w, forgotTmpl, forgotData{LoginChallenge: loginChallenge})
		return
	}

	var issuedCode string
	if _, err := handler.store.GetUserByEmail(r.Context(), email); err == nil {
		issuedCode = utils.GenerateNumericCode(6)
		if err := handler.redis.SaveVerificationCode(r.Context(), "reset", email, issuedCode); err == nil {
			// Send errors are logged but never surfaced — the response must look
			// identical whether or not the account exists (no enumeration).
			if err := sendResetCode(r.Context(), handler.mailer, email, issuedCode); err != nil {
				slog.Error("reset: failed to send code email", "err", err)
			}
		}
	}

	target := url.URL{Path: "/auth/reset"}
	query := target.Query()
	query.Set("email", email)
	if loginChallenge != "" {
		query.Set("login_challenge", loginChallenge)
	}
	// In debug builds (no real mailbox) surface the code so dev and tests can
	// continue the flow. Never emitted in production.
	if handler.debug && issuedCode != "" {
		query.Set("code", issuedCode)
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

func (handler *RecoveryHandler) serveReset(w http.ResponseWriter, r *http.Request) {
	render(w, resetTmpl, resetData{
		LoginChallenge: r.URL.Query().Get("login_challenge"),
		Email:          r.URL.Query().Get("email"),
	})
}

// handleVerifyResetCode checks the emailed reset code. On success it releases the
// recovery-wrapped AMK (so the browser can unwrap it with the recovery phrase)
// and issues a one-time reset token for the final submission.
func (handler *RecoveryHandler) handleVerifyResetCode(w http.ResponseWriter, r *http.Request) {
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

	stored, err := handler.redis.GetVerificationCode(r.Context(), "reset", email)
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

	userKey, err := handler.store.GetUserKeyByEmail(r.Context(), email)
	if err != nil {
		jsonError(w, "Failed to load recovery key", http.StatusInternalServerError)
		return
	}

	resetToken := utils.GenerateRandomString(32)
	if err := handler.redis.SaveResetToken(r.Context(), resetToken, email); err != nil {
		jsonError(w, "Failed to start reset", http.StatusInternalServerError)
		return
	}
	_ = handler.redis.DeleteVerificationCode(r.Context(), "reset", email)

	writeJSON(w, map[string]any{
		"reset_token":          resetToken,
		"recovery_wrapped_amk": userKey.RecoveryWrappedAMK,
	})
}

type resetRequest struct {
	ResetToken         string `json:"reset_token"`
	Password           string `json:"password"`
	PasswordWrappedAMK string `json:"password_wrapped_amk"`
	Argon2Salt         string `json:"argon2_salt"`
	Argon2Time         int    `json:"argon2_time"`
	Argon2Memory       int    `json:"argon2_memory"`
	Argon2Threads      int    `json:"argon2_threads"`
	Argon2Keylen       int    `json:"argon2_keylen"`
}

// handleReset writes the new password hash and re-wrapped AMK. The reset token
// is consumed (single use); the AMK itself was unwrapped and re-wrapped entirely
// in the browser, so the server only ever sees the opaque new wrapper.
func (handler *RecoveryHandler) handleReset(w http.ResponseWriter, r *http.Request) {
	var body resetRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if body.ResetToken == "" {
		jsonError(w, "Missing reset token", http.StatusBadRequest)
		return
	}
	if len(body.Password) < 8 {
		jsonError(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if body.PasswordWrappedAMK == "" || body.Argon2Salt == "" ||
		body.Argon2Time <= 0 || body.Argon2Memory <= 0 ||
		body.Argon2Threads <= 0 || body.Argon2Keylen <= 0 {
		jsonError(w, "Missing key material", http.StatusBadRequest)
		return
	}

	email, err := handler.redis.ConsumeResetToken(r.Context(), body.ResetToken)
	if errors.Is(err, cache.ErrNotFound) {
		jsonError(w, "Reset session expired — please start over", http.StatusBadRequest)
		return
	}
	if err != nil {
		jsonError(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	user, err := handler.store.GetUserByEmail(r.Context(), email)
	if err != nil {
		jsonError(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	err = handler.store.ResetPassword(r.Context(), &database.ResetPasswordParams{
		UserID:             user.ID.ID.(string),
		Password:           body.Password,
		PasswordWrappedAMK: body.PasswordWrappedAMK,
		Argon2Salt:         body.Argon2Salt,
		Argon2Time:         body.Argon2Time,
		Argon2Memory:       body.Argon2Memory,
		Argon2Threads:      body.Argon2Threads,
		Argon2Keylen:       body.Argon2Keylen,
	})
	if err != nil {
		jsonError(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"ok": true})
}

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

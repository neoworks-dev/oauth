package vault

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/neoworks/oauth/internal/mail"
	"github.com/neoworks/oauth/internal/wire"
)

const (
	codeDigits         = 6
	codeSendWindow     = 10 * time.Minute
	codeSendMaxPerMail = 3
	codeSendMaxPerIP   = 20
	codeMaxAttempts    = 5
)

func newNumericCode(digits int) string {
	upperBound := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	number, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%0*d", digits, number)
}

func emailDigest(email string) string {
	return wire.EncodeBase64URL(wire.Hash([]byte(email)))
}

// codeSendLimited counts a code request against the per-email and per-IP limits.
func (server *Server) codeSendLimited(request *http.Request, purpose, email string) bool {
	if server.exceeded(request, "code_send:"+purpose+":"+emailDigest(email), codeSendMaxPerMail, codeSendWindow) {
		return true
	}
	return server.exceeded(request, "code_send_ip:"+clientIP(request), codeSendMaxPerIP, codeSendWindow)
}

// issueCode stores a fresh code and emails it. In debug builds a failed send is
// tolerated and the code is returned so development needs no mailbox.
func (server *Server) issueCode(ctx context.Context, purpose, email, subject string) (string, error) {
	code := newNumericCode(codeDigits)
	if err := server.state.SaveVerificationCode(ctx, purpose, email, code); err != nil {
		return "", err
	}
	message := mail.Message{
		To:      []string{email},
		Subject: subject,
		Text:    "Your Neoworks verification code is " + code + ". It expires in 10 minutes.",
	}
	err := server.mailer.Send(ctx, message)
	if err != nil {
		slog.Error("failed to send verification code", "purpose", purpose, "error", err)
		if !server.config.Debug {
			return "", err
		}
	}
	return code, nil
}

// checkCode compares a submitted code with the stored one. Too many wrong
// guesses burn the code. The result is "ok", "expired", "wrong" or "locked".
func (server *Server) checkCode(request *http.Request, purpose, email, submitted string) string {
	ctx := request.Context()
	stored, err := server.state.GetVerificationCode(ctx, purpose, email)
	if err != nil {
		return "expired"
	}
	attemptKey := "code_attempts:" + purpose + ":" + emailDigest(email)
	if server.exceeded(request, attemptKey, codeMaxAttempts, codeSendWindow) {
		_ = server.state.DeleteVerificationCode(ctx, purpose, email)
		return "locked"
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(strings.TrimSpace(submitted))) != 1 {
		return "wrong"
	}
	_ = server.state.DeleteVerificationCode(ctx, purpose, email)
	return "ok"
}

func codeFailureResponse(response http.ResponseWriter, result string) {
	switch result {
	case "expired":
		writeError(response, http.StatusBadRequest, "code_expired")
	case "locked":
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
	default:
		writeError(response, http.StatusBadRequest, "code_incorrect")
	}
}

func (server *Server) codeResponse(response http.ResponseWriter, code string) {
	body := map[string]any{"sent": true}
	if server.config.Debug {
		body["code"] = code
	}
	writeJSON(response, http.StatusOK, body)
}

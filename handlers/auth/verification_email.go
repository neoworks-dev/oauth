package auth

import (
	"context"
	"fmt"

	"github.com/neoworks/auth/email"
)

// sendVerificationCode emails a signup verification code.
func sendVerificationCode(ctx context.Context, mailer email.Sender, to, code string) error {
	return mailer.Send(ctx, email.Message{
		To:      []string{to},
		Subject: "Verify your NeoWorks email",
		Text:    fmt.Sprintf("Your NeoWorks verification code is %s. It expires in 10 minutes.", code),
		HTML:    codeEmailHTML("Confirm your email", "Use this code to finish creating your NeoWorks account.", code),
	})
}

// sendResetCode emails a password-reset verification code.
func sendResetCode(ctx context.Context, mailer email.Sender, to, code string) error {
	return mailer.Send(ctx, email.Message{
		To:      []string{to},
		Subject: "Reset your NeoWorks password",
		Text:    fmt.Sprintf("Your NeoWorks password reset code is %s. It expires in 10 minutes. If you didn't request this, you can ignore this email.", code),
		HTML:    codeEmailHTML("Reset your password", "Use this code to continue resetting your NeoWorks password. If you didn't request this, you can ignore this email.", code),
	})
}

func codeEmailHTML(heading, intro, code string) string {
	return fmt.Sprintf(`<div style="font-family: system-ui, sans-serif; max-width: 420px; margin: 0 auto; color: #1a1a1a;">
  <h1 style="font-size: 18px;">%s</h1>
  <p style="font-size: 14px; color: #555;">%s</p>
  <p style="font-size: 32px; font-weight: 600; letter-spacing: 6px; margin: 24px 0;">%s</p>
  <p style="font-size: 12px; color: #888;">This code expires in 10 minutes.</p>
</div>`, heading, intro, code)
}

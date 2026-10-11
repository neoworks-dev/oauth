// Package mail sends transactional email. Without SMTP credentials it degrades
// to a sender that logs each message, so development works without a mailbox.
package mail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	netmail "net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type Message struct {
	To      []string
	Subject string
	Text    string
}

type Sender interface {
	Send(ctx context.Context, message Message) error
}

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

func ConfigFromEnv() Config {
	return Config{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     os.Getenv("SMTP_PORT"),
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
	}
}

func NewSender(config Config) Sender {
	if config.Host == "" || config.Username == "" || config.From == "" {
		return loggingSender{}
	}
	port := config.Port
	if port == "" {
		port = "587"
	}
	return &smtpSender{config: config, port: port}
}

type smtpSender struct {
	config Config
	port   string
}

func (sender *smtpSender) Send(_ context.Context, message Message) error {
	if len(message.To) == 0 {
		return fmt.Errorf("mail: no recipients")
	}
	address := sender.config.Host + ":" + sender.port
	auth := smtp.PlainAuth("", sender.config.Username, sender.config.Password, sender.config.Host)
	body := buildMIME(sender.config.From, message, time.Now(), newMessageID(sender.config.From))
	err := smtp.SendMail(address, auth, sender.config.From, message.To, body)
	if err != nil {
		return fmt.Errorf("mail: send: %w", err)
	}
	return nil
}

func buildMIME(from string, message Message, sentAt time.Time, messageID string) []byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Date: %s\r\n", sentAt.Format(time.RFC1123Z))
	fmt.Fprintf(&builder, "Message-ID: %s\r\n", messageID)
	fmt.Fprintf(&builder, "From: %s\r\n", from)
	fmt.Fprintf(&builder, "To: %s\r\n", strings.Join(message.To, ", "))
	fmt.Fprintf(&builder, "Subject: %s\r\n", message.Subject)
	builder.WriteString("MIME-Version: 1.0\r\n")
	builder.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n")
	builder.WriteString(message.Text)
	return []byte(builder.String())
}

// newMessageID makes a globally unique Message-ID on the sender's domain.
func newMessageID(from string) string {
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	return "<" + hex.EncodeToString(random) + "@" + domainOf(from) + ">"
}

func domainOf(from string) string {
	address, err := netmail.ParseAddress(from)
	if err != nil {
		return "localhost"
	}
	_, domain, found := strings.Cut(address.Address, "@")
	if !found {
		return "localhost"
	}
	return domain
}

type loggingSender struct{}

func (loggingSender) Send(_ context.Context, message Message) error {
	slog.Info("mail not sent, SMTP is not configured", "to", message.To, "subject", message.Subject)
	return nil
}

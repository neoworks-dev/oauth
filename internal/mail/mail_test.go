package mail

import (
	"bytes"
	netmail "net/mail"
	"regexp"
	"testing"
	"time"
)

func TestMessagesCarryDateAndMessageID(t *testing.T) {
	sentAt := time.Date(2026, 10, 11, 16, 5, 0, 0, time.UTC)
	from := "Neoworks <info@neoworks.dev>"
	raw := buildMIME(from, Message{To: []string{"someone@example.com"}, Subject: "Confirm", Text: "Hi"}, sentAt, newMessageID(from))

	parsed, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid message: %v", err)
	}
	date, err := parsed.Header.Date()
	if err != nil || !date.Equal(sentAt) {
		t.Errorf("Date = %v, %v; want %v", date, err, sentAt)
	}
	messageID := parsed.Header.Get("Message-ID")
	if !regexp.MustCompile(`^<[0-9a-f]{32}@neoworks\.dev>$`).MatchString(messageID) {
		t.Errorf("Message-ID = %q", messageID)
	}
}

func TestMessageIDsAreUnique(t *testing.T) {
	if newMessageID("info@neoworks.dev") == newMessageID("info@neoworks.dev") {
		t.Fatal("two messages got the same Message-ID")
	}
}

func TestMessageIDFallsBackWhenTheSenderIsNotAnAddress(t *testing.T) {
	if domainOf("not an address") != "localhost" {
		t.Fatal("an unparsable sender must still give a valid Message-ID")
	}
}

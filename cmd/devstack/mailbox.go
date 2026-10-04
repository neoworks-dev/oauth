package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/neoworks/oauth/internal/mail"
)

// mailbox keeps every message sent, so browser tests can read emailed links.
type mailbox struct {
	mutex    sync.Mutex
	messages []mail.Message
}

func (box *mailbox) Send(_ context.Context, message mail.Message) error {
	box.mutex.Lock()
	defer box.mutex.Unlock()
	box.messages = append(box.messages, message)
	return nil
}

// latestFor returns the newest message to an address.
func (box *mailbox) latestFor(address string) *mail.Message {
	box.mutex.Lock()
	defer box.mutex.Unlock()
	for index := len(box.messages) - 1; index >= 0; index-- {
		for _, recipient := range box.messages[index].To {
			if recipient == address {
				message := box.messages[index]
				return &message
			}
		}
	}
	return nil
}

// handler serves GET /__devstack/mail?to=<address> as JSON.
func (box *mailbox) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/__devstack/mail" {
			next.ServeHTTP(response, request)
			return
		}
		message := box.latestFor(request.URL.Query().Get("to"))
		if message == nil {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]string{"subject": message.Subject, "text": message.Text})
	})
}

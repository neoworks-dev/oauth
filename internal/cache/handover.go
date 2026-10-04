package cache

import (
	"context"
	"time"
)

const HandoverTTL = 120 * time.Second

// HandoverSession carries an AMK from the authenticator to the browser vault.
// BrowserSession is the hash of the vault session token that created it; only
// that session may read the sealed value.
type HandoverSession struct {
	BrowserSession string `json:"browser_session"`
	UserID         string `json:"user_id"`
	Delivered      bool   `json:"delivered"`
	DeviceID       string `json:"device_id,omitempty"`
	Sealed         string `json:"sealed,omitempty"`
}

func (store *Store) CreateHandover(ctx context.Context, sessionID string, session HandoverSession) (bool, error) {
	encoded, err := marshal(session)
	if err != nil {
		return false, err
	}
	return store.client.SetNX(ctx, "handover:"+sessionID, encoded, HandoverTTL).Result()
}

func (store *Store) GetHandover(ctx context.Context, sessionID string) (*HandoverSession, error) {
	var session HandoverSession
	err := store.getJSON(ctx, "handover:"+sessionID, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// DeliverHandover stores the sealed AMK, keeping the remaining time to live.
func (store *Store) DeliverHandover(ctx context.Context, sessionID string, session HandoverSession) error {
	key := "handover:" + sessionID
	remaining, err := store.client.TTL(ctx, key).Result()
	if err != nil {
		return err
	}
	if remaining <= 0 {
		return ErrNotFound
	}
	return store.saveJSON(ctx, key, session, remaining)
}

func (store *Store) TakeHandover(ctx context.Context, sessionID string) (*HandoverSession, error) {
	var session HandoverSession
	err := store.takeJSON(ctx, "handover:"+sessionID, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

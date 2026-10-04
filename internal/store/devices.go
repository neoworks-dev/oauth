package store

import (
	"context"
	"time"
)

type Device struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

const deviceColumns = "record::id(id) AS id, record::id(user) AS user, name, kind, created_at, last_seen_at, revoked_at"

func (store *Store) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	return firstRow[Device](ctx, store,
		"SELECT "+deviceColumns+" FROM device WHERE id = $id LIMIT 1",
		map[string]any{"id": recordID("device", deviceID)})
}

// RegisterDevice records a login from a device. A revoked device, or a device
// id owned by another account, is refused.
func (store *Store) RegisterDevice(ctx context.Context, userID, deviceID, name, kind string) error {
	existing, err := store.GetDevice(ctx, deviceID)
	if err == ErrNotFound {
		return store.createDevice(ctx, userID, deviceID, name, kind)
	}
	if err != nil {
		return err
	}
	if existing.UserID != userID || existing.RevokedAt != nil {
		return ErrRevoked
	}
	return execute(ctx, store,
		"UPDATE $id SET last_seen_at = time::now(), name = $name",
		map[string]any{"id": recordID("device", deviceID), "name": name})
}

func (store *Store) createDevice(ctx context.Context, userID, deviceID, name, kind string) error {
	return execute(ctx, store, `
		CREATE $id SET user = $user, name = $name, kind = $kind,
			created_at = time::now(), last_seen_at = time::now()`,
		map[string]any{
			"id":   recordID("device", deviceID),
			"user": recordID("user", userID),
			"name": name,
			"kind": kind,
		})
}

// IsDeviceActive reports whether the device exists for the user and is not revoked.
func (store *Store) IsDeviceActive(ctx context.Context, userID, deviceID string) (bool, error) {
	device, err := store.GetDevice(ctx, deviceID)
	if err == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return device.UserID == userID && device.RevokedAt == nil, nil
}

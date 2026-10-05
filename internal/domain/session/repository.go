package session

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the storage contract for sessions (Redis is the intended adapter).
// Adapters should derive the storage TTL from Session.ExpiresAt.
type Repository interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, id string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error

	// DeleteAllByUserID removes every session of a user (e.g. "log out everywhere").
	DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error
}

package user

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the storage contract for User aggregate roots.
// It remains completely decoupled from database drivers (e.g., pgx, sqlx, gorm).
type Repository interface {
	// Persistence Operations
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByEmailOrUsername(ctx context.Context, identifier string) (*User, error)

	// Update persists mutated domain fields or partial param updates
	Update(ctx context.Context, user *User) error

	// Status & Lifecycle Transitions
	// (Note: Implementation adapters run SQL updates matching the entity state)
	Delete(ctx context.Context, id uuid.UUID) error
}

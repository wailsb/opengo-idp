package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// Column order shared by every SELECT and scanUser.
const userColumns = `id, email, username, password_hash, is_enabled, is_deleted, created_at, updated_at`

type UserRepository struct {
	db DBTX
}

var _ user.Repository = (*UserRepository)(nil)

func NewUserRepository(db DBTX) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO users (`+userColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.ID, u.Email, u.Username, u.PasswordHash, u.IsActive, u.IsDeleted, u.CreatedAt, u.UpdatedAt,
	)
	if _, ok := constraintViolation(err, codeUniqueViolation); ok {
		return user.ErrUserAlreadyExists
	}
	return err
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	return r.getOne(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	return r.getOne(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email)
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	return r.getOne(ctx, `SELECT `+userColumns+` FROM users WHERE username = $1`, username)
}

// GetByEmailOrUsername prefers an email match, so a username that happens to equal
// another user's email can never shadow that user.
func (r *UserRepository) GetByEmailOrUsername(ctx context.Context, identifier string) (*user.User, error) {
	return r.getOne(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE email = $1 OR username = $1
		ORDER BY (email = $1) DESC
		LIMIT 1`, identifier)
}

func (r *UserRepository) Update(ctx context.Context, u *user.User) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE users
		SET email = $2,
		    username = $3,
		    password_hash = $4,
		    is_enabled = $5,
		    is_deleted = $6,
		    updated_at = $7
		WHERE id = $1`,
		u.ID, u.Email, u.Username, u.PasswordHash, u.IsActive, u.IsDeleted, u.UpdatedAt,
	)
	if _, ok := constraintViolation(err, codeUniqueViolation); ok {
		return user.ErrUserAlreadyExists
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return user.ErrUserNotFound
	}
	return nil
}

// Delete soft-deletes the user, matching the state user.User.Delete produces. The row
// is kept so audit history and email/username uniqueness are preserved.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE users
		SET is_deleted = TRUE, is_enabled = FALSE, updated_at = NOW()
		WHERE id = $1 AND NOT is_deleted`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return r.deleteMissReason(ctx, id)
	}
	return nil
}

// deleteMissReason distinguishes an unknown user from an already deleted one.
func (r *UserRepository) deleteMissReason(ctx context.Context, id uuid.UUID) error {
	var exists bool
	if err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return user.ErrUserDeleted
	}
	return user.ErrUserNotFound
}

func (r *UserRepository) getOne(ctx context.Context, query string, arg any) (*user.User, error) {
	var u user.User
	err := r.db.QueryRow(ctx, query, arg).Scan(
		&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.IsActive, &u.IsDeleted, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	u.CreatedAt = u.CreatedAt.UTC()
	u.UpdatedAt = u.UpdatedAt.UTC()
	return &u, nil
}

package user

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUserInactive       = errors.New("user is not active")
	ErrUserAlreadyActive  = errors.New("user is already active")
	ErrUserDeleted        = errors.New("user is deleted")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	Username     string
	IsActive     bool
	IsDeleted    bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
type UpdateUserParams struct {
	Email    *string
	Username *string
	IsActive *bool
}

// NewUser expects a plain text password and hashes it internally
func NewUser(email, plainPassword, username string) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	return &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		Username:     username,
		IsActive:     true,
		IsDeleted:    false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// NewUserFromHash builds a user from an already hashed password, for callers that own
// the hashing policy (e.g. a configured bcrypt cost).
func NewUserFromHash(email, passwordHash, username string) *User {
	now := time.Now().UTC()
	return &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		Username:     username,
		IsActive:     true,
		IsDeleted:    false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

func (u *User) Disable() error {
	if u.IsDeleted {
		return ErrUserDeleted
	}
	if !u.IsActive {
		return ErrUserInactive
	}

	u.IsActive = false
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (u *User) Enable() error {
	if u.IsDeleted {
		return ErrUserDeleted
	}
	if u.IsActive {
		return ErrUserAlreadyActive
	}

	u.IsActive = true
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (u *User) Delete() error {
	if u.IsDeleted {
		return ErrUserDeleted
	}

	u.IsDeleted = true
	u.IsActive = false
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (u *User) UpdateInfo(params UpdateUserParams) error {
	if u.IsDeleted {
		return ErrUserDeleted
	}
	if !u.IsActive {
		return ErrUserInactive
	}

	hasChanges := false

	if params.Email != nil && *params.Email != u.Email {
		u.Email = *params.Email
		hasChanges = true
	}

	if params.Username != nil && *params.Username != u.Username {
		u.Username = *params.Username
		hasChanges = true
	}

	if params.IsActive != nil && *params.IsActive != u.IsActive {
		u.IsActive = *params.IsActive
		hasChanges = true
	}

	if hasChanges {
		u.UpdatedAt = time.Now().UTC()
	}

	return nil
}

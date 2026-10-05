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
	ErrUnActiveUser       = errors.New("user is not active")
	ErrDeletedUser        = errors.New("user is deleted")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type User struct {
	UUID         uuid.UUID
	Email        string
	PasswordHash string
	Username     string
	IsActive     bool
	IsDeleted    bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func NewUser(email, passwordHash, username string) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwordHash), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &User{
		UUID:         uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		Username:     username,
		IsActive:     true,
		IsDeleted:    false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}
func (u *User) Disable() (bool, error) {
	if !u.IsActive {
		return false, ErrUnActiveUser
	}
	u.IsActive = false
	u.UpdatedAt = time.Now()
	return true, nil
}
func (u *User) Enable() (bool, error) {
	if u.IsActive {
		return false, ErrUnActiveUser
	}
	u.IsActive = true
	u.UpdatedAt = time.Now()
	return true, nil
}
func (u *User) Delete() (bool, error) {
	if u.IsDeleted {
		return false, ErrDeletedUser
	}
	u.IsDeleted = true
	u.UpdatedAt = time.Now()
	return true, nil
}
func (u *User) UpdateInfo(uUpdate *User) (bool, error) {
	if u.IsDeleted {
		return false, ErrDeletedUser
	}
	if !u.IsActive {
		return false, ErrUnActiveUser
	}
	UpdatedUser := &User{
		UUID:         uUpdate.UUID==nil? u.UUID : uUpdate.UUID,
		Email:        uUpdate.Email==nil? u.UUID : uUpdate.UUID,
		PasswordHash: uUpdate.PasswordHash==nil? u.UUID : uUpdate.UUID,
		Username:     uUpdate.Username==nil? u.UUID : uUpdate.UUID,
		IsActive:     uUpdate.IsActive==nil? u.UUID : uUpdate.UUID,
		IsDeleted:    uUpdate.IsDeleted==nil? u.UUID : uUpdate.UUID,
		CreatedAt:    uUpdate.CreatedAt==nil? u.UUID : uUpdate.UUID,
		UpdatedAt:    uUpdate.UpdatedAt==nil? time.Now() : uUpdate.UpdatedAt,
	}
	u = UpdatedUser
	return true, nil
}

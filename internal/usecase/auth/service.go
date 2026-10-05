package auth

import (
	"errors"
	"time"

	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserInactive       = errors.New("user account is disabled")
)

type PasswordHasher interface {
	Compare(hashedPassword, plainPassword string) error
	Hash(password string) (string, error)
}

type Service struct {
	userRepo    user.Repository
	sessionRepo session.Repository
	hasher      PasswordHasher
	sessionTTL  time.Duration
}

func NewService(
	u user.Repository,
	s session.Repository,
	hasher PasswordHasher,
	sessionTTL time.Duration,
) *Service {
	return &Service{
		userRepo:    u,
		sessionRepo: s,
		hasher:      hasher,
		sessionTTL:  sessionTTL,
	}
}

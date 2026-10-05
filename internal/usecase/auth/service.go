package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/wailsb/opengo-idp/internal/domain/access"
	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserInactive       = errors.New("user account is disabled")
	ErrInvalidClient      = errors.New("unknown client")
	// ErrInvalidGrant covers every refresh failure (bad token, dead session, disabled
	// user) so callers can map it to the OAuth2 "invalid_grant" error.
	ErrInvalidGrant = errors.New("invalid or expired grant")
)

type PasswordHasher interface {
	Compare(hashedPassword, plainPassword string) error
	Hash(password string) (string, error)
}

// Deps are the collaborators of the auth Service.
type Deps struct {
	Users    user.Repository
	Sessions session.Repository
	Clients  client.Repository
	Access   access.Repository
	Hasher   PasswordHasher
	Tokens   token.Service

	SessionTTL time.Duration
	// AccessTokenTTL is only reported back as TokenPair.ExpiresIn; the token service
	// decides the real lifetime.
	AccessTokenTTL time.Duration
}

type Service struct {
	userRepo       user.Repository
	sessionRepo    session.Repository
	clientRepo     client.Repository
	accessRepo     access.Repository
	hasher         PasswordHasher
	tokens         token.Service
	sessionTTL     time.Duration
	accessTokenTTL time.Duration

	// dummyHash is compared against when the user does not exist, so an unknown
	// email takes as long as a wrong password and cannot be detected by timing.
	dummyHash string
}

func NewService(d Deps) (*Service, error) {
	if d.Users == nil || d.Sessions == nil || d.Clients == nil || d.Access == nil || d.Hasher == nil || d.Tokens == nil {
		return nil, errors.New("auth: all dependencies are required")
	}
	if d.SessionTTL <= 0 {
		return nil, errors.New("auth: session TTL must be positive")
	}

	dummy, err := d.Hasher.Hash("timing-equalizer-not-a-real-password")
	if err != nil {
		return nil, fmt.Errorf("auth: compute dummy hash: %w", err)
	}

	return &Service{
		userRepo:       d.Users,
		sessionRepo:    d.Sessions,
		clientRepo:     d.Clients,
		accessRepo:     d.Access,
		hasher:         d.Hasher,
		tokens:         d.Tokens,
		sessionTTL:     d.SessionTTL,
		accessTokenTTL: d.AccessTokenTTL,
		dummyHash:      dummy,
	}, nil
}

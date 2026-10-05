// Package admin holds provisioning usecases: creating users and registering clients.
package admin

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

var (
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrInvalidUsername = errors.New("username must be 3-32 characters of letters, digits, '.', '_' or '-'")
	ErrWeakPassword    = errors.New("password must be between 8 and 72 bytes")
)

const (
	minPasswordLen = 8
	// bcrypt ignores everything past 72 bytes.
	maxPasswordLen = 72
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,32}$`)

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type Service struct {
	users   user.Repository
	clients client.Repository
	hasher  PasswordHasher
}

func NewService(users user.Repository, clients client.Repository, hasher PasswordHasher) *Service {
	return &Service{users: users, clients: clients, hasher: hasher}
}

type CreateUserInput struct {
	Email    string
	Username string
	Password string
}

// CreateUser validates input and stores a new active user. Emails are stored
// lowercased; login normalizes the same way. Returns user.ErrUserAlreadyExists on a
// duplicate email or username.
func (s *Service) CreateUser(ctx context.Context, in CreateUserInput) (*user.User, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	addr, err := mail.ParseAddress(email)
	// Reject display-name forms like "Bob <bob@x.com>": only a bare address is accepted.
	if err != nil || addr.Address != email {
		return nil, ErrInvalidEmail
	}

	username := strings.TrimSpace(in.Username)
	if !usernamePattern.MatchString(username) {
		return nil, ErrInvalidUsername
	}

	if len(in.Password) < minPasswordLen || len(in.Password) > maxPasswordLen {
		return nil, ErrWeakPassword
	}

	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	u := user.NewUserFromHash(email, hash, username)
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

type CreateClientInput struct {
	Name           string
	RedirectURIs   []string
	GrantTypes     []string
	IsConfidential bool
}

// CreateClient registers a client and returns it with its plain secret (empty for
// public clients). The secret is not recoverable afterwards.
func (s *Service) CreateClient(ctx context.Context, in CreateClientInput) (*client.Client, string, error) {
	c, secret, err := client.NewClient(in.Name, in.RedirectURIs, in.GrantTypes, in.IsConfidential)
	if err != nil {
		return nil, "", err
	}
	if err := s.clients.Create(ctx, c); err != nil {
		return nil, "", err
	}
	return c, secret, nil
}

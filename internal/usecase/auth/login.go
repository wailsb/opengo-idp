package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

type LoginInput struct {
	Email     string
	Password  string
	IPAddress string
	UserAgent string
	ClientID  string
}

type LoginOutput struct {
	Session *session.Session
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	// 1. Retrieve user from PostgreSQL
	u, err := s.userRepo.GetByEmail(ctx, input.Email)
	if errors.Is(err, user.ErrUserNotFound) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	// 2. Verify password hash
	if err := s.hasher.Compare(u.PasswordHash, input.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Checked only after the password, so the response doesn't reveal account
	// status to someone who doesn't know the password.
	if u.IsDeleted {
		return nil, ErrInvalidCredentials
	}
	if !u.IsActive {
		return nil, ErrUserInactive
	}

	// 3. Construct domain Session (SSO session, shared by all clients)
	sess := session.NewSession(u.ID, input.UserAgent, input.IPAddress, s.sessionTTL)

	// 4. Persist active session into Redis
	if err := s.sessionRepo.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &LoginOutput{Session: sess}, nil
}

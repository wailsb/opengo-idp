package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

type LoginInput struct {
	// Identifier is the user's email or username.
	Identifier string
	Password   string
	IPAddress  string
	UserAgent  string
	// ClientID is optional; when set the client must exist and an ID token is issued.
	ClientID string
	Nonce    string
}

type LoginOutput struct {
	Session *session.Session
	Tokens  *TokenPair
}

// NormalizeIdentifier lowercases emails (stored lowercased at registration) and
// leaves usernames untouched.
func NormalizeIdentifier(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if strings.Contains(identifier, "@") {
		return strings.ToLower(identifier)
	}
	return identifier
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	c, err := s.lookupClient(ctx, input.ClientID)
	if err != nil {
		return nil, err
	}

	// 1. Retrieve user from PostgreSQL
	u, err := s.userRepo.GetByEmailOrUsername(ctx, NormalizeIdentifier(input.Identifier))
	if errors.Is(err, user.ErrUserNotFound) {
		_ = s.hasher.Compare(s.dummyHash, input.Password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
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

	// 5. Issue tokens bound to the session; drop the session if that fails so no
	// orphan session is left behind.
	tokens, err := s.issueTokens(ctx, u, sess.ID, c, input.Nonce)
	if err != nil {
		_ = s.sessionRepo.Delete(ctx, sess.ID)
		return nil, err
	}

	return &LoginOutput{Session: sess, Tokens: tokens}, nil
}

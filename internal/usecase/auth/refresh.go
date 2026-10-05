package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

type RefreshInput struct {
	RefreshToken string
	// ClientID is optional; when set the client must exist and a new ID token is issued.
	ClientID string
}

// Refresh exchanges a refresh token for a new token pair. The refresh token is only
// honoured while its session is alive and the user is still active, so logout or
// disabling the account cuts off refresh immediately.
func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*TokenPair, error) {
	c, err := s.lookupClient(ctx, input.ClientID)
	if err != nil {
		return nil, err
	}

	claims, err := s.tokens.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	sess, err := s.ValidateSession(ctx, claims.SessionID)
	if isSessionGone(err) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("validate session: %w", err)
	}
	if sess.UserID != claims.UserID {
		return nil, ErrInvalidGrant
	}

	u, err := s.userRepo.GetByID(ctx, claims.UserID)
	if errors.Is(err, user.ErrUserNotFound) {
		_ = s.sessionRepo.Delete(ctx, sess.ID)
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if u.IsDeleted || !u.IsActive {
		_ = s.sessionRepo.Delete(ctx, sess.ID)
		return nil, ErrInvalidGrant
	}

	return s.issueTokens(ctx, u, sess.ID, c, "")
}

func isSessionGone(err error) bool {
	return errors.Is(err, session.ErrSessionNotFound) ||
		errors.Is(err, session.ErrSessionExpired) ||
		errors.Is(err, session.ErrSessionRevoked)
}

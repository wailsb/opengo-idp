package auth

import (
	"context"

	"github.com/wailsb/opengo-idp/internal/domain/session"
)

func (s *Service) ValidateSession(ctx context.Context, sessionID string) (*session.Session, error) {
	sess, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err // Returns session.ErrSessionNotFound
	}

	if err := sess.IsValid(); err != nil {
		return nil, err
	}

	return sess, nil
}

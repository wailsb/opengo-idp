package auth

import (
	"context"

	"github.com/google/uuid"
)

func (s *Service) Logout(ctx context.Context, sessionID string) error {
	return s.sessionRepo.Delete(ctx, sessionID)
}

func (s *Service) LogoutAllDevices(ctx context.Context, userID uuid.UUID) error {
	return s.sessionRepo.DeleteAllByUserID(ctx, userID)
}

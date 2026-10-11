package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

type RefreshInput struct {
	RefreshToken string
	// ClientID is optional for first-party refresh; when the token itself carries
	// an azp (OAuth code flow) it must match.
	ClientID string
}

// Refresh exchanges a refresh token for a new token pair. The refresh token is only
// honoured while its session is alive, its user is still active, and (if the token
// is bound to a client via azp) the presenting client matches.
func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*TokenPair, error) {
	c, err := s.lookupClient(ctx, input.ClientID)
	if err != nil {
		return nil, err
	}

	claims, err := s.tokens.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// azp binding: if the refresh token was issued to a specific client, the
	// presenting client must be that same client. Timing-safe compare so a client
	// can't probe for others' azps.
	if claims.AuthorizedTo != "" {
		if c == nil {
			return nil, ErrInvalidGrant
		}
		if subtle.ConstantTimeCompare([]byte(c.ClientID), []byte(claims.AuthorizedTo)) != 1 {
			return nil, ErrInvalidGrant
		}
		if !c.IsGrantTypeAllowed(client.GrantTypeRefreshToken) {
			return nil, ErrUnauthorizedClient
		}
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

	// Preserve the original scope set when refreshing an OAuth-issued token so
	// the new tokens carry the same aud/scope. First-party refresh (no scope on
	// the token) keeps the legacy "all claims" behaviour.
	clientID := ""
	if c != nil {
		clientID = c.ClientID
	}
	scopes := token.ParseScopes(claims.Scope)
	return s.issueTokensScoped(ctx, u, sess.ID, clientID, "", scopes, true)
}

func isSessionGone(err error) bool {
	return errors.Is(err, session.ErrSessionNotFound) ||
		errors.Is(err, session.ErrSessionExpired) ||
		errors.Is(err, session.ErrSessionRevoked)
}

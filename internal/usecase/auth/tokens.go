package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// TokenPair is the result of a successful login or refresh. IDToken is only set
// when the request named a client.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int64 // seconds until the access token expires
}

// lookupClient returns nil for an empty clientID, ErrInvalidClient for an unknown one.
func (s *Service) lookupClient(ctx context.Context, clientID string) (*client.Client, error) {
	if clientID == "" {
		return nil, nil
	}
	c, err := s.clientRepo.GetByClientID(ctx, clientID)
	if errors.Is(err, client.ErrClientNotFound) {
		return nil, ErrInvalidClient
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	return c, nil
}

func (s *Service) issueTokens(ctx context.Context, u *user.User, sessionID string, c *client.Client, nonce string) (*TokenPair, error) {
	summary, err := s.accessRepo.GetUserAccessSummary(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("get access summary: %w", err)
	}

	accessTok, err := s.tokens.GenerateAccessToken(u, summary)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}
	refreshTok, err := s.tokens.GenerateRefreshToken(u, sessionID)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	pair := &TokenPair{
		AccessToken:  accessTok,
		RefreshToken: refreshTok,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
	}
	if c != nil {
		pair.IDToken, err = s.tokens.GenerateIDToken(u, summary, c.ClientID, nonce)
		if err != nil {
			return nil, fmt.Errorf("generate id token: %w", err)
		}
	}
	return pair, nil
}

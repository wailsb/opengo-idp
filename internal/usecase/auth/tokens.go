package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// TokenPair is the result of a successful login, authorization-code exchange or
// refresh. IDToken is only set when the request named a client (and asked for
// the "openid" scope, when scopes are supplied). RefreshToken is only set when
// the "offline_access" scope was requested or no scopes were supplied.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int64 // seconds until the access token expires
	Scope        string
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

// issueTokens is the legacy helper used by first-party /login and refresh.
// It issues access + refresh (+ id, if a client was named), ignoring scopes.
func (s *Service) issueTokens(ctx context.Context, u *user.User, sessionID string, c *client.Client, nonce string) (*TokenPair, error) {
	clientID := ""
	if c != nil {
		clientID = c.ClientID
	}
	return s.issueTokensScoped(ctx, u, sessionID, clientID, nonce, nil, true)
}

// issueTokensScoped mints the pair for a given scope set. When issueRefresh is false
// no refresh token is produced (e.g. refresh grant that was asked without offline_access
// — though we actually use the stored scope there).
func (s *Service) issueTokensScoped(ctx context.Context, u *user.User, sessionID, clientID, nonce string, scopes []string, issueRefresh bool) (*TokenPair, error) {
	summary, err := s.accessRepo.GetUserAccessSummary(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("get access summary: %w", err)
	}

	var audience []string
	if clientID != "" {
		audience = []string{clientID}
	}

	accessTok, err := s.tokens.GenerateAccessTokenFor(token.AccessTokenRequest{
		User:     u,
		Summary:  summary,
		Scopes:   scopes,
		ClientID: clientID,
		Audience: audience,
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	pair := &TokenPair{
		AccessToken: accessTok,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       token.JoinScopes(scopes),
	}

	wantRefresh := issueRefresh && (len(scopes) == 0 || token.HasScope(scopes, token.ScopeOfflineAccess))
	if wantRefresh {
		refreshTok, err := s.tokens.GenerateRefreshTokenFor(token.RefreshTokenRequest{
			User:      u,
			SessionID: sessionID,
			Scopes:    scopes,
			ClientID:  clientID,
		})
		if err != nil {
			return nil, fmt.Errorf("generate refresh token: %w", err)
		}
		pair.RefreshToken = refreshTok
	}

	// ID token requires an audience (clientID) and, when scopes are supplied,
	// the "openid" scope.
	issueID := clientID != "" && (len(scopes) == 0 || token.HasScope(scopes, token.ScopeOpenID))
	if issueID {
		idTok, err := s.tokens.GenerateIDTokenFor(token.IDTokenRequest{
			User:        u,
			Summary:     summary,
			ClientID:    clientID,
			Nonce:       nonce,
			Scopes:      scopes,
			AccessToken: accessTok,
		})
		if err != nil {
			return nil, fmt.Errorf("generate id token: %w", err)
		}
		pair.IDToken = idTok
	}

	return pair, nil
}

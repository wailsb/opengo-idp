package auth

import (
	"context"
	"fmt"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/token"
)

// ClientCredentialsInput feeds the client_credentials grant. The caller has
// already authenticated the client.
type ClientCredentialsInput struct {
	Client *client.Client
	Scopes []string
}

// ClientCredentials issues an access token for machine-to-machine access. No
// user, no refresh token; the subject is the client ID.
func (s *Service) ClientCredentials(_ context.Context, in ClientCredentialsInput) (*TokenPair, error) {
	if in.Client == nil {
		return nil, ErrInvalidClient
	}
	if !in.Client.IsConfidential {
		return nil, ErrUnauthorizedClient
	}
	if !in.Client.IsGrantTypeAllowed(client.GrantTypeClientCredentials) {
		return nil, ErrUnauthorizedClient
	}

	accessTok, err := s.tokens.GenerateClientAccessToken(token.ClientAccessTokenRequest{
		ClientID: in.Client.ClientID,
		Scopes:   in.Scopes,
		Audience: []string{in.Client.ClientID},
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	return &TokenPair{
		AccessToken: accessTok,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       token.JoinScopes(in.Scopes),
	}, nil
}

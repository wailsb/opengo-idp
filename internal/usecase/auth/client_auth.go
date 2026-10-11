package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/wailsb/opengo-idp/internal/domain/client"
)

// ClientCredentials carried on /token (RFC 6749 §2.3). Fields come from either the
// Basic header or the request body; the transport layer parses the preference.
type ClientAuthInput struct {
	ClientID     string
	ClientSecret string
	// PresentedBasic is true if the client identified itself via HTTP Basic.
	// It only affects error reporting (Basic failures get a WWW-Authenticate challenge).
	PresentedBasic bool
}

// AuthenticateClient resolves the client and checks its secret in constant time.
// Public clients MUST NOT present a secret: doing so is treated as an invalid
// client. The caller enforces that public clients supply PKCE.
func (s *Service) AuthenticateClient(ctx context.Context, in ClientAuthInput) (*client.Client, error) {
	if in.ClientID == "" {
		return nil, ErrInvalidClient
	}
	c, err := s.clientRepo.GetByClientID(ctx, in.ClientID)
	if errors.Is(err, client.ErrClientNotFound) {
		return nil, ErrInvalidClient
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	if c.IsConfidential {
		if in.ClientSecret == "" {
			return nil, ErrInvalidClient
		}
		if !c.VerifySecret(in.ClientSecret) {
			return nil, ErrInvalidClient
		}
	} else {
		// Public client: no secret allowed. Compare in constant time to avoid
		// leaking whether the field was looked at.
		if subtle.ConstantTimeCompare([]byte(in.ClientSecret), []byte("")) != 1 {
			return nil, ErrInvalidClient
		}
	}
	return c, nil
}

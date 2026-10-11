package token

import (
	"context"

	"github.com/wailsb/opengo-idp/internal/domain/access"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// KeyProvider supplies the signing key pair. Implementations return concrete crypto
// types (e.g. *rsa.PrivateKey / *rsa.PublicKey or *ecdsa equivalents); the KID is
// published in the JWKS and set in the JWT header for key rotation.
type KeyProvider interface {
	GetPrivateKey() interface{}
	GetPublicKey() interface{}
	GetKID() string
}

// AccessTokenRequest carries everything needed to mint an access token for a user.
// Audience, Scopes and ClientID are optional; empty values are omitted from claims.
type AccessTokenRequest struct {
	User     *user.User
	Summary  *access.UserAccessSummary
	Scopes   []string
	ClientID string
	Audience []string
}

// RefreshTokenRequest describes a user-bound refresh token. Scope narrows the
// grant; ClientID populates the azp claim so refresh is bound to one client.
type RefreshTokenRequest struct {
	User      *user.User
	SessionID string
	Scopes    []string
	ClientID  string
}

// IDTokenRequest holds the inputs for an OIDC ID token. AccessToken is optional:
// when present it is used to compute the at_hash claim (OIDC Core §3.1.3.6).
type IDTokenRequest struct {
	User        *user.User
	Summary     *access.UserAccessSummary
	ClientID    string
	Nonce       string
	Scopes      []string
	AccessToken string
}

// ClientAccessTokenRequest holds the inputs for a client_credentials access token
// (no user, Subject = ClientID).
type ClientAccessTokenRequest struct {
	ClientID string
	Scopes   []string
	Audience []string
}

// Service issues and validates JWTs.
type Service interface {
	GenerateAccessToken(user *user.User, summary *access.UserAccessSummary) (string, error)
	GenerateRefreshToken(user *user.User, sessionID string) (string, error)
	GenerateIDToken(user *user.User, summary *access.UserAccessSummary, clientID, nonce string) (string, error)

	// GenerateAccessTokenFor is the richer variant: it supports scopes, audience
	// and the azp (authorized party) claim.
	GenerateAccessTokenFor(req AccessTokenRequest) (string, error)
	GenerateRefreshTokenFor(req RefreshTokenRequest) (string, error)
	GenerateIDTokenFor(req IDTokenRequest) (string, error)
	GenerateClientAccessToken(req ClientAccessTokenRequest) (string, error)

	// ValidateToken verifies signature, expiry and issuer of an access token. It must
	// return ErrInvalidTokenType for any token whose TokenType is not TypeAccess.
	ValidateToken(tokenStr string) (*AccessTokenClaims, error)

	// ValidateRefreshToken verifies a refresh token. Callers must still check that the
	// referenced session is valid before issuing new tokens.
	ValidateRefreshToken(tokenStr string) (*RefreshTokenClaims, error)

	// GetJWKS returns the public keys as a JSON Web Key Set ({"keys": [...]}).
	GetJWKS(ctx context.Context) (map[string]interface{}, error)
}

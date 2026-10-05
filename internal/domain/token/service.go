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

// Service issues and validates JWTs.
type Service interface {
	GenerateAccessToken(user *user.User, summary *access.UserAccessSummary) (string, error)
	GenerateRefreshToken(user *user.User, sessionID string) (string, error)
	GenerateIDToken(user *user.User, summary *access.UserAccessSummary, clientID, nonce string) (string, error)

	// ValidateToken verifies signature, expiry and issuer of an access token. It must
	// return ErrInvalidTokenType for any token whose TokenType is not TypeAccess.
	ValidateToken(tokenStr string) (*AccessTokenClaims, error)

	// ValidateRefreshToken verifies a refresh token. Callers must still check that the
	// referenced session is valid before issuing new tokens.
	ValidateRefreshToken(tokenStr string) (*RefreshTokenClaims, error)

	// GetJWKS returns the public keys as a JSON Web Key Set ({"keys": [...]}).
	GetJWKS(ctx context.Context) (map[string]interface{}, error)
}

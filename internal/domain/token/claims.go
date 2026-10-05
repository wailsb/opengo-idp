package token

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token is expired")
	ErrInvalidTokenType = errors.New("unexpected token type")
)

// Type distinguishes token kinds so one cannot be replayed as another
// (e.g. a refresh token presented as an access token).
type Type string

const (
	TypeAccess  Type = "access"
	TypeRefresh Type = "refresh"
	TypeID      Type = "id"
)

// AccessTokenClaims authorize API calls. Subject holds the user ID; Attributes carry
// ABAC inputs evaluated by resource servers.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	TokenType   Type              `json:"token_type"`
	UserID      uuid.UUID         `json:"uid"`
	Email       string            `json:"email,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Permissions []string          `json:"permissions,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// IDTokenClaims assert the user's identity to an OIDC client. Audience must be the
// client ID, and Nonce must echo the value sent in the authorization request.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	TokenType         Type              `json:"token_type"`
	UserID            uuid.UUID         `json:"uid"`
	Email             string            `json:"email,omitempty"`
	PreferredUsername string            `json:"preferred_username,omitempty"`
	Nonce             string            `json:"nonce,omitempty"`
	Roles             []string          `json:"roles,omitempty"`
	Permissions       []string          `json:"permissions,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
}

// RefreshTokenClaims bind a refresh token to a server-side session (sid), so revoking
// the session invalidates the refresh token.
type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	TokenType Type      `json:"token_type"`
	UserID    uuid.UUID `json:"uid"`
	SessionID string    `json:"sid"`
}

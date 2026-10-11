// Package authcode models the one-shot authorization codes exchanged at the
// /token endpoint for an access token (OAuth 2.0 §4.1, OIDC Core §3.1).
package authcode

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrAuthCodeNotFound = errors.New("authorization code not found")
	ErrAuthCodeExpired  = errors.New("authorization code expired")
	ErrInvalidCode      = errors.New("invalid authorization code")
)

// MaxTTL caps the lifetime of an authorization code (OAuth 2.1 §4.1.3 recommends ≤60s).
const MaxTTL = 60 * time.Second

// codeBytes is the entropy of a generated code (256 bits).
const codeBytes = 32

// Challenge method values registered by RFC 7636 §4.3.
const (
	ChallengeMethodPlain = "plain"
	ChallengeMethodS256  = "S256"
)

// AuthCode is a single-use authorization code bound to the client that received
// it, the user who authenticated, and the exact redirect_uri they came through.
// Storage adapters MUST enforce single-use semantics: once GetAndDelete returns a
// code it must never be returnable again.
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              uuid.UUID
	SessionID           string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// New creates an AuthCode with a random code and an expiry no later than MaxTTL
// from now. ttl ≤ 0 or ttl > MaxTTL returns an error so callers cannot accidentally
// extend the window.
func New(clientID, redirectURI, scope, nonce, challenge, method string, userID uuid.UUID, sessionID string, ttl time.Duration) (*AuthCode, error) {
	if clientID == "" {
		return nil, errors.New("authcode: client ID is required")
	}
	if redirectURI == "" {
		return nil, errors.New("authcode: redirect URI is required")
	}
	if ttl <= 0 || ttl > MaxTTL {
		return nil, errors.New("authcode: ttl must be in (0, MaxTTL]")
	}
	if method != "" && method != ChallengeMethodPlain && method != ChallengeMethodS256 {
		return nil, errors.New("authcode: unsupported code_challenge_method")
	}
	if challenge == "" && method != "" {
		return nil, errors.New("authcode: challenge method set without a challenge")
	}

	now := time.Now().UTC()
	return &AuthCode{
		Code:                newCode(),
		ClientID:            clientID,
		UserID:              userID,
		SessionID:           sessionID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		CreatedAt:           now,
		ExpiresAt:           now.Add(ttl),
	}, nil
}

// IsExpired reports whether now is past ExpiresAt.
func (a *AuthCode) IsExpired() bool {
	return !time.Now().UTC().Before(a.ExpiresAt)
}

// newCode returns a URL-safe random token. crypto/rand.Read never returns an
// error on supported platforms; it crashes the program if the OS source fails.
func newCode() string {
	b := make([]byte, codeBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

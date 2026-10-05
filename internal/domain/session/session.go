package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionRevoked  = errors.New("session is revoked")
	ErrSessionExpired  = errors.New("session is expired")
	ErrInvalidDuration = errors.New("duration must be positive")
)

// sessionIDBytes is the entropy of a session ID (256 bits).
const sessionIDBytes = 32

// Session is a stateful login session. ID is an opaque, unguessable token.
type Session struct {
	ID        string
	UserID    uuid.UUID
	UserAgent string
	IPAddress string
	IsRevoked bool
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewSession(userID uuid.UUID, userAgent, ipAddress string, ttl time.Duration) *Session {
	now := time.Now().UTC()
	return &Session{
		ID:        newSessionID(),
		UserID:    userID,
		UserAgent: userAgent,
		IPAddress: ipAddress,
		IsRevoked: false,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
}

// newSessionID returns a URL-safe random token. crypto/rand.Read never returns an
// error on supported platforms; it crashes the program if the OS source fails.
func newSessionID() string {
	b := make([]byte, sessionIDBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Session) IsValid() error {
	if s.IsRevoked {
		return ErrSessionRevoked
	}
	if !time.Now().UTC().Before(s.ExpiresAt) {
		return ErrSessionExpired
	}
	return nil
}

// Revoke marks the session as unusable. Revoking an already revoked session is a no-op.
func (s *Session) Revoke() {
	s.IsRevoked = true
}

// Extend pushes ExpiresAt forward by duration. Only valid sessions can be extended,
// so a revoked or expired session cannot be revived.
func (s *Session) Extend(duration time.Duration) error {
	if duration <= 0 {
		return ErrInvalidDuration
	}
	if err := s.IsValid(); err != nil {
		return err
	}

	s.ExpiresAt = s.ExpiresAt.Add(duration).UTC()
	return nil
}

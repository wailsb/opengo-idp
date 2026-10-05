package session

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewSession(t *testing.T) {
	uid := uuid.New()
	a := NewSession(uid, "ua", "1.2.3.4", time.Hour)
	b := NewSession(uid, "ua", "1.2.3.4", time.Hour)

	if a.ID == "" || a.ID == b.ID {
		t.Fatal("session IDs must be unique and non-empty")
	}
	if len(a.ID) != 43 { // base64url of 32 bytes, unpadded
		t.Errorf("id length = %d", len(a.ID))
	}
	if a.UserID != uid || a.IsRevoked || a.ExpiresAt.Sub(a.CreatedAt) != time.Hour {
		t.Errorf("unexpected session: %+v", a)
	}
	if err := a.IsValid(); err != nil {
		t.Errorf("new session invalid: %v", err)
	}
}

func TestIsValid(t *testing.T) {
	s := NewSession(uuid.New(), "", "", time.Hour)
	s.ExpiresAt = time.Now().Add(-time.Second)
	if err := s.IsValid(); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expired: %v", err)
	}

	s = NewSession(uuid.New(), "", "", time.Hour)
	s.Revoke()
	s.Revoke() // idempotent
	if err := s.IsValid(); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("revoked: %v", err)
	}
}

func TestExtend(t *testing.T) {
	s := NewSession(uuid.New(), "", "", time.Hour)
	before := s.ExpiresAt

	if err := s.Extend(30 * time.Minute); err != nil || s.ExpiresAt.Sub(before) != 30*time.Minute {
		t.Fatalf("extend: %v", err)
	}
	if err := s.Extend(0); !errors.Is(err, ErrInvalidDuration) {
		t.Errorf("zero duration: %v", err)
	}

	s.Revoke()
	if err := s.Extend(time.Hour); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("revoked session must not be extendable: %v", err)
	}
}

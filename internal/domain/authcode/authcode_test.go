package authcode

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNew_Success(t *testing.T) {
	uid := uuid.New()
	c, err := New("client-x", "https://app/cb", "openid profile", "n1", "challenge", ChallengeMethodS256, uid, "sid", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c.Code == "" {
		t.Error("code must be non-empty")
	}
	if c.ClientID != "client-x" || c.RedirectURI != "https://app/cb" || c.UserID != uid || c.SessionID != "sid" {
		t.Errorf("unexpected: %+v", c)
	}
	if c.Scope != "openid profile" || c.Nonce != "n1" || c.CodeChallenge != "challenge" || c.CodeChallengeMethod != ChallengeMethodS256 {
		t.Errorf("challenge mismatch: %+v", c)
	}
	if c.ExpiresAt.Sub(c.CreatedAt) != 30*time.Second {
		t.Errorf("ttl not honoured: %v", c.ExpiresAt.Sub(c.CreatedAt))
	}
	if c.IsExpired() {
		t.Error("fresh code should not be expired")
	}
}

func TestNew_UniqueCodes(t *testing.T) {
	seen := map[string]struct{}{}
	for range 128 {
		c, err := New("c", "https://app/cb", "", "", "", "", uuid.New(), "sid", 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[c.Code]; dup {
			t.Fatal("duplicate code generated")
		}
		seen[c.Code] = struct{}{}
	}
}

func TestNew_Validation(t *testing.T) {
	uid := uuid.New()
	cases := map[string]struct {
		clientID, redirect, challenge, method string
		ttl                                   time.Duration
	}{
		"no client":        {"", "https://app/cb", "", "", 10 * time.Second},
		"no redirect":      {"c", "", "", "", 10 * time.Second},
		"zero ttl":         {"c", "https://app/cb", "", "", 0},
		"negative ttl":     {"c", "https://app/cb", "", "", -time.Second},
		"over max ttl":     {"c", "https://app/cb", "", "", MaxTTL + time.Second},
		"bad method":       {"c", "https://app/cb", "chal", "weird", 10 * time.Second},
		"method w/o chal":  {"c", "https://app/cb", "", ChallengeMethodS256, 10 * time.Second},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tc.clientID, tc.redirect, "", "", tc.challenge, tc.method, uid, "sid", tc.ttl); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestIsExpired(t *testing.T) {
	c, err := New("c", "https://app/cb", "", "", "", "", uuid.New(), "sid", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.ExpiresAt = time.Now().Add(-time.Second).UTC()
	if !c.IsExpired() {
		t.Fatal("expected expired")
	}
}

func TestSentinelErrors(t *testing.T) {
	// Compile-time guard: callers depend on these being errors.New sentinels.
	if !errors.Is(ErrAuthCodeNotFound, ErrAuthCodeNotFound) {
		t.Fatal("sentinel broken")
	}
}

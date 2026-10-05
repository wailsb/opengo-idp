package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wailsb/opengo-idp/internal/domain/session"
)

var ctx = context.Background()

func TestNewService_RequiresDeps(t *testing.T) {
	if _, err := NewService(Deps{}); err == nil {
		t.Fatal("expected error for missing deps")
	}
	f := newFixture()
	_, err := NewService(Deps{
		Users: f.users, Sessions: f.sessions, Clients: f.clients, Access: f.access,
		Hasher: f.hasher, Tokens: f.tokens, SessionTTL: 0,
	})
	if err == nil {
		t.Fatal("expected error for zero session TTL")
	}
}

func TestLogin_Success(t *testing.T) {
	f := newFixture()

	for _, ident := range []string{"alice@example.com", "  ALICE@example.com ", "alice"} {
		out, err := f.svc.Login(ctx, LoginInput{Identifier: ident, Password: alicePassword, IPAddress: "1.2.3.4", UserAgent: "ua"})
		if err != nil {
			t.Fatalf("login %q: %v", ident, err)
		}
		if out.Session.UserID != f.alice.ID || out.Session.IPAddress != "1.2.3.4" {
			t.Errorf("session mismatch: %+v", out.Session)
		}
		if _, err := f.sessions.GetByID(ctx, out.Session.ID); err != nil {
			t.Errorf("session not persisted: %v", err)
		}
		tp := out.Tokens
		if tp.AccessToken != "access:"+f.alice.ID.String() ||
			tp.RefreshToken != "refresh:"+f.alice.ID.String()+":"+out.Session.ID ||
			tp.TokenType != "Bearer" || tp.ExpiresIn != 900 {
			t.Errorf("unexpected tokens: %+v", tp)
		}
		if tp.IDToken != "" {
			t.Error("id token must only be issued when a client is named")
		}
	}
}

func TestLogin_WithClientIssuesIDToken(t *testing.T) {
	f := newFixture()
	out, err := f.svc.Login(ctx, LoginInput{Identifier: "alice", Password: alicePassword, ClientID: "web-app", Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "id:" + f.alice.ID.String() + ":web-app:n1"; out.Tokens.IDToken != want {
		t.Errorf("id token = %q, want %q", out.Tokens.IDToken, want)
	}
}

func TestLogin_Failures(t *testing.T) {
	cases := map[string]struct {
		setup   func(f *fixture)
		input   LoginInput
		wantErr error
	}{
		"wrong password": {
			input:   LoginInput{Identifier: "alice", Password: "nope"},
			wantErr: ErrInvalidCredentials,
		},
		"unknown user": {
			input:   LoginInput{Identifier: "bob@example.com", Password: "x"},
			wantErr: ErrInvalidCredentials,
		},
		"deleted user": {
			setup:   func(f *fixture) { f.alice.IsDeleted, f.alice.IsActive = true, false },
			input:   LoginInput{Identifier: "alice", Password: alicePassword},
			wantErr: ErrInvalidCredentials,
		},
		"inactive user": {
			setup:   func(f *fixture) { f.alice.IsActive = false },
			input:   LoginInput{Identifier: "alice", Password: alicePassword},
			wantErr: ErrUserInactive,
		},
		"inactive user wrong password hides status": {
			setup:   func(f *fixture) { f.alice.IsActive = false },
			input:   LoginInput{Identifier: "alice", Password: "nope"},
			wantErr: ErrInvalidCredentials,
		},
		"unknown client": {
			input:   LoginInput{Identifier: "alice", Password: alicePassword, ClientID: "ghost"},
			wantErr: ErrInvalidClient,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			if tc.setup != nil {
				tc.setup(f)
			}
			_, err := f.svc.Login(ctx, tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			if len(f.sessions.byID) != 0 {
				t.Error("no session must be created on failure")
			}
		})
	}
}

func TestLogin_UnknownUserStillComparesHash(t *testing.T) {
	f := newFixture()
	_, _ = f.svc.Login(ctx, LoginInput{Identifier: "nobody", Password: "x"})
	if f.hasher.compares != 1 {
		t.Fatalf("compares = %d, want 1 (timing equalizer)", f.hasher.compares)
	}
}

func TestLogin_InfrastructureErrors(t *testing.T) {
	t.Run("user repo error is not masked as bad credentials", func(t *testing.T) {
		f := newFixture()
		f.users.err = errors.New("db down")
		_, err := f.svc.Login(ctx, LoginInput{Identifier: "alice", Password: alicePassword})
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("session create error", func(t *testing.T) {
		f := newFixture()
		f.sessions.createErr = errors.New("redis down")
		if _, err := f.svc.Login(ctx, LoginInput{Identifier: "alice", Password: alicePassword}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("token failure rolls back session", func(t *testing.T) {
		f := newFixture()
		f.tokens.accessErr = errors.New("signer broken")
		if _, err := f.svc.Login(ctx, LoginInput{Identifier: "alice", Password: alicePassword}); err == nil {
			t.Fatal("expected error")
		}
		if len(f.sessions.byID) != 0 {
			t.Error("orphan session left behind")
		}
	})
}

func login(t *testing.T, f *fixture) *LoginOutput {
	t.Helper()
	out, err := f.svc.Login(ctx, LoginInput{Identifier: "alice", Password: alicePassword})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRefresh_Success(t *testing.T) {
	f := newFixture()
	out := login(t, f)

	tp, err := f.svc.Refresh(ctx, RefreshInput{RefreshToken: out.Tokens.RefreshToken, ClientID: "web-app"})
	if err != nil {
		t.Fatal(err)
	}
	if tp.AccessToken == "" || tp.RefreshToken != out.Tokens.RefreshToken || tp.IDToken == "" {
		t.Errorf("unexpected tokens: %+v", tp)
	}
}

func TestRefresh_Failures(t *testing.T) {
	cases := map[string]struct {
		mutate   func(t *testing.T, f *fixture, out *LoginOutput) string
		clientID string
		wantErr  error
	}{
		"malformed token": {
			mutate:  func(*testing.T, *fixture, *LoginOutput) string { return "garbage" },
			wantErr: ErrInvalidGrant,
		},
		"after logout": {
			mutate: func(t *testing.T, f *fixture, out *LoginOutput) string {
				if err := f.svc.Logout(ctx, out.Session.ID); err != nil {
					t.Fatal(err)
				}
				return out.Tokens.RefreshToken
			},
			wantErr: ErrInvalidGrant,
		},
		"revoked session": {
			mutate: func(_ *testing.T, f *fixture, out *LoginOutput) string {
				f.sessions.byID[out.Session.ID].IsRevoked = true
				return out.Tokens.RefreshToken
			},
			wantErr: ErrInvalidGrant,
		},
		"expired session": {
			mutate: func(_ *testing.T, f *fixture, out *LoginOutput) string {
				f.sessions.byID[out.Session.ID].ExpiresAt = time.Now().Add(-time.Second)
				return out.Tokens.RefreshToken
			},
			wantErr: ErrInvalidGrant,
		},
		"session belongs to another user": {
			mutate: func(_ *testing.T, f *fixture, out *LoginOutput) string {
				return "refresh:" + uuid.NewString() + ":" + out.Session.ID
			},
			wantErr: ErrInvalidGrant,
		},
		"user disabled": {
			mutate: func(_ *testing.T, f *fixture, out *LoginOutput) string {
				f.alice.IsActive = false
				return out.Tokens.RefreshToken
			},
			wantErr: ErrInvalidGrant,
		},
		"unknown client": {
			mutate: func(_ *testing.T, f *fixture, out *LoginOutput) string {
				return out.Tokens.RefreshToken
			},
			clientID: "ghost",
			wantErr:  ErrInvalidClient,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			out := login(t, f)
			tok := tc.mutate(t, f, out)
			_, err := f.svc.Refresh(ctx, RefreshInput{RefreshToken: tok, ClientID: tc.clientID})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestRefresh_DisabledUserLosesSession(t *testing.T) {
	f := newFixture()
	out := login(t, f)
	f.alice.IsActive = false
	_, _ = f.svc.Refresh(ctx, RefreshInput{RefreshToken: out.Tokens.RefreshToken})
	if _, err := f.sessions.GetByID(ctx, out.Session.ID); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("session of disabled user should be deleted, got %v", err)
	}
}

func TestValidateSession(t *testing.T) {
	f := newFixture()
	out := login(t, f)

	if s, err := f.svc.ValidateSession(ctx, out.Session.ID); err != nil || s.ID != out.Session.ID {
		t.Fatalf("valid session: %v", err)
	}
	if _, err := f.svc.ValidateSession(ctx, "missing"); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("missing: got %v", err)
	}
	f.sessions.byID[out.Session.ID].IsRevoked = true
	if _, err := f.svc.ValidateSession(ctx, out.Session.ID); !errors.Is(err, session.ErrSessionRevoked) {
		t.Errorf("revoked: got %v", err)
	}
}

func TestLogoutAllDevices(t *testing.T) {
	f := newFixture()
	a, b := login(t, f), login(t, f)
	if err := f.svc.LogoutAllDevices(ctx, f.alice.ID); err != nil {
		t.Fatal(err)
	}
	for _, out := range []*LoginOutput{a, b} {
		if _, err := f.sessions.GetByID(ctx, out.Session.ID); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("session %s survived logout-all", out.Session.ID)
		}
	}
}

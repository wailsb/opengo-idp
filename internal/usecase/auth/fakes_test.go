package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/wailsb/opengo-idp/internal/domain/access"
	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// fakeHasher "hashes" by prefixing, and counts comparisons so tests can assert the
// timing equalizer runs for unknown users.
type fakeHasher struct {
	compares int
}

func (h *fakeHasher) Hash(p string) (string, error) { return "hash:" + p, nil }
func (h *fakeHasher) Compare(hashed, plain string) error {
	h.compares++
	if hashed != "hash:"+plain {
		return errors.New("mismatch")
	}
	return nil
}

type fakeUsers struct {
	user.Repository // unimplemented methods panic
	byID            map[uuid.UUID]*user.User
	err             error
}

func (r *fakeUsers) add(u *user.User) { r.byID[u.ID] = u }

func (r *fakeUsers) GetByID(_ context.Context, id uuid.UUID) (*user.User, error) {
	if r.err != nil {
		return nil, r.err
	}
	u, ok := r.byID[id]
	if !ok {
		return nil, user.ErrUserNotFound
	}
	return u, nil
}

func (r *fakeUsers) GetByEmailOrUsername(_ context.Context, ident string) (*user.User, error) {
	if r.err != nil {
		return nil, r.err
	}
	for _, u := range r.byID {
		if u.Email == ident || u.Username == ident {
			return u, nil
		}
	}
	return nil, user.ErrUserNotFound
}

type fakeSessions struct {
	mu        sync.Mutex
	byID      map[string]*session.Session
	createErr error
}

func (r *fakeSessions) Create(_ context.Context, s *session.Session) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *s
	r.byID[s.ID] = &cp
	return nil
}

func (r *fakeSessions) GetByID(_ context.Context, id string) (*session.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	cp := *s
	return &cp, nil
}

func (r *fakeSessions) Update(_ context.Context, s *session.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *s
	r.byID[s.ID] = &cp
	return nil
}

func (r *fakeSessions) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
	return nil
}

func (r *fakeSessions) DeleteAllByUserID(_ context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.byID {
		if s.UserID == userID {
			delete(r.byID, id)
		}
	}
	return nil
}

type fakeClients struct {
	client.Repository
	byClientID map[string]*client.Client
}

func (r *fakeClients) GetByClientID(_ context.Context, id string) (*client.Client, error) {
	c, ok := r.byClientID[id]
	if !ok {
		return nil, client.ErrClientNotFound
	}
	return c, nil
}

type fakeAccess struct {
	access.Repository
	summary *access.UserAccessSummary
	err     error
}

func (r *fakeAccess) GetUserAccessSummary(context.Context, uuid.UUID) (*access.UserAccessSummary, error) {
	return r.summary, r.err
}

// fakeTokens issues readable strings instead of JWTs:
//
//	access:<uid>   refresh:<uid>:<sid>   id:<uid>:<client>:<nonce>
type fakeTokens struct {
	token.Service
	accessErr error
}

func (f *fakeTokens) GenerateAccessToken(u *user.User, _ *access.UserAccessSummary) (string, error) {
	if f.accessErr != nil {
		return "", f.accessErr
	}
	return "access:" + u.ID.String(), nil
}

func (f *fakeTokens) GenerateRefreshToken(u *user.User, sid string) (string, error) {
	return "refresh:" + u.ID.String() + ":" + sid, nil
}

func (f *fakeTokens) GenerateIDToken(u *user.User, _ *access.UserAccessSummary, clientID, nonce string) (string, error) {
	return "id:" + u.ID.String() + ":" + clientID + ":" + nonce, nil
}

func (f *fakeTokens) ValidateRefreshToken(tok string) (*token.RefreshTokenClaims, error) {
	parts := strings.SplitN(tok, ":", 3)
	if len(parts) != 3 || parts[0] != "refresh" {
		return nil, token.ErrInvalidToken
	}
	uid, err := uuid.Parse(parts[1])
	if err != nil {
		return nil, token.ErrInvalidToken
	}
	return &token.RefreshTokenClaims{TokenType: token.TypeRefresh, UserID: uid, SessionID: parts[2]}, nil
}

type fixture struct {
	svc      *Service
	users    *fakeUsers
	sessions *fakeSessions
	clients  *fakeClients
	access   *fakeAccess
	hasher   *fakeHasher
	tokens   *fakeTokens
	alice    *user.User
}

const alicePassword = "correct-horse"

func newFixture() *fixture {
	f := &fixture{
		users:    &fakeUsers{byID: map[uuid.UUID]*user.User{}},
		sessions: &fakeSessions{byID: map[string]*session.Session{}},
		clients: &fakeClients{byClientID: map[string]*client.Client{
			"web-app": {ID: uuid.New(), ClientID: "web-app", Name: "Web"},
		}},
		access: &fakeAccess{summary: &access.UserAccessSummary{Roles: []string{"admin"}}},
		hasher: &fakeHasher{},
		tokens: &fakeTokens{},
	}
	f.alice = &user.User{
		ID:           uuid.New(),
		Email:        "alice@example.com",
		Username:     "alice",
		PasswordHash: "hash:" + alicePassword,
		IsActive:     true,
	}
	f.users.add(f.alice)

	svc, err := NewService(Deps{
		Users:          f.users,
		Sessions:       f.sessions,
		Clients:        f.clients,
		Access:         f.access,
		Hasher:         f.hasher,
		Tokens:         f.tokens,
		SessionTTL:     time.Hour,
		AccessTokenTTL: 15 * time.Minute,
	})
	if err != nil {
		panic(err)
	}
	f.svc = svc
	return f
}

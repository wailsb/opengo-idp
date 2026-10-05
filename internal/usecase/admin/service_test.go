package admin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

type fakeHasher struct{}

func (fakeHasher) Hash(p string) (string, error) { return "hash:" + p, nil }

type fakeUsers struct {
	user.Repository
	created []*user.User
}

func (r *fakeUsers) Create(_ context.Context, u *user.User) error {
	for _, e := range r.created {
		if e.Email == u.Email || e.Username == u.Username {
			return user.ErrUserAlreadyExists
		}
	}
	r.created = append(r.created, u)
	return nil
}

type fakeClients struct {
	client.Repository
	created []*client.Client
}

func (r *fakeClients) Create(_ context.Context, c *client.Client) error {
	r.created = append(r.created, c)
	return nil
}

var ctx = context.Background()

func TestCreateUser_Success(t *testing.T) {
	users := &fakeUsers{}
	s := NewService(users, &fakeClients{}, fakeHasher{})

	u, err := s.CreateUser(ctx, CreateUserInput{Email: "  Alice@Example.COM ", Username: "alice", Password: "longenough"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("email not normalized: %q", u.Email)
	}
	if u.PasswordHash != "hash:longenough" {
		t.Errorf("password not hashed with configured hasher: %q", u.PasswordHash)
	}
	if !u.IsActive || u.IsDeleted || len(users.created) != 1 {
		t.Errorf("unexpected state: %+v", u)
	}
}

func TestCreateUser_Validation(t *testing.T) {
	valid := CreateUserInput{Email: "a@b.co", Username: "alice", Password: "longenough"}
	cases := map[string]struct {
		mutate  func(*CreateUserInput)
		wantErr error
	}{
		"empty email":       {func(in *CreateUserInput) { in.Email = "" }, ErrInvalidEmail},
		"no at":             {func(in *CreateUserInput) { in.Email = "alice" }, ErrInvalidEmail},
		"display name":      {func(in *CreateUserInput) { in.Email = "Bob <bob@x.com>" }, ErrInvalidEmail},
		"short username":    {func(in *CreateUserInput) { in.Username = "ab" }, ErrInvalidUsername},
		"username with @":   {func(in *CreateUserInput) { in.Username = "a@b" }, ErrInvalidUsername},
		"username w/ space": {func(in *CreateUserInput) { in.Username = "al ice" }, ErrInvalidUsername},
		"short password":    {func(in *CreateUserInput) { in.Password = "short" }, ErrWeakPassword},
		"too long password": {func(in *CreateUserInput) { in.Password = strings.Repeat("x", 73) }, ErrWeakPassword},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			s := NewService(&fakeUsers{}, &fakeClients{}, fakeHasher{})
			if _, err := s.CreateUser(ctx, in); !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	s := NewService(&fakeUsers{}, &fakeClients{}, fakeHasher{})
	in := CreateUserInput{Email: "a@b.co", Username: "alice", Password: "longenough"}
	if _, err := s.CreateUser(ctx, in); err != nil {
		t.Fatal(err)
	}
	in.Email = "A@B.CO" // same email after normalization
	in.Username = "other"
	if _, err := s.CreateUser(ctx, in); !errors.Is(err, user.ErrUserAlreadyExists) {
		t.Fatalf("got %v, want ErrUserAlreadyExists", err)
	}
}

func TestCreateClient(t *testing.T) {
	clients := &fakeClients{}
	s := NewService(&fakeUsers{}, clients, fakeHasher{})

	c, secret, err := s.CreateClient(ctx, CreateClientInput{
		Name:           "Backend",
		GrantTypes:     []string{client.GrantTypeClientCredentials},
		IsConfidential: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || !c.VerifySecret(secret) || len(clients.created) != 1 {
		t.Errorf("confidential client not created correctly")
	}

	c, secret, err = s.CreateClient(ctx, CreateClientInput{
		Name:         "SPA",
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{client.GrantTypeAuthorizationCode},
	})
	if err != nil || secret != "" || c.IsConfidential {
		t.Errorf("public client: %+v, %q, %v", c, secret, err)
	}

	if _, _, err := s.CreateClient(ctx, CreateClientInput{Name: ""}); !errors.Is(err, client.ErrInvalidClientName) {
		t.Errorf("got %v, want ErrInvalidClientName", err)
	}
}

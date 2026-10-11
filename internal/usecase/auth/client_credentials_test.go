package auth

import (
	"errors"
	"testing"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/token"
)

func TestClientCredentials_Success(t *testing.T) {
	f := newFixture()
	c := &client.Client{
		ClientID:          "api",
		IsConfidential:    true,
		AllowedGrantTypes: []string{client.GrantTypeClientCredentials},
	}
	f.clients.byClientID["api"] = c

	tp, err := f.svc.ClientCredentials(ctx, ClientCredentialsInput{Client: c, Scopes: []string{token.ScopeProfile}})
	if err != nil {
		t.Fatal(err)
	}
	if tp.AccessToken != "client-access:api" || tp.RefreshToken != "" || tp.IDToken != "" {
		t.Fatalf("unexpected pair: %+v", tp)
	}
}

func TestClientCredentials_RejectsPublic(t *testing.T) {
	f := newFixture()
	c := &client.Client{
		ClientID:          "pub",
		AllowedGrantTypes: []string{client.GrantTypeClientCredentials},
	}
	if _, err := f.svc.ClientCredentials(ctx, ClientCredentialsInput{Client: c}); !errors.Is(err, ErrUnauthorizedClient) {
		t.Fatalf("got %v", err)
	}
}

func TestClientCredentials_EnforcesGrantType(t *testing.T) {
	f := newFixture()
	c := &client.Client{
		ClientID:          "api",
		IsConfidential:    true,
		AllowedGrantTypes: []string{client.GrantTypeAuthorizationCode},
	}
	if _, err := f.svc.ClientCredentials(ctx, ClientCredentialsInput{Client: c}); !errors.Is(err, ErrUnauthorizedClient) {
		t.Fatalf("got %v", err)
	}
}

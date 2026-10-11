package auth

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/wailsb/opengo-idp/internal/domain/client"
)

func TestAuthenticateClient_Confidential(t *testing.T) {
	f := newFixture()
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	c := &client.Client{
		ClientID:         "conf",
		IsConfidential:   true,
		ClientSecretHash: string(hash),
	}
	f.clients.byClientID["conf"] = c

	got, err := f.svc.AuthenticateClient(ctx, ClientAuthInput{ClientID: "conf", ClientSecret: "s3cret"})
	if err != nil || got != c {
		t.Fatalf("got %v err=%v", got, err)
	}
	if _, err := f.svc.AuthenticateClient(ctx, ClientAuthInput{ClientID: "conf", ClientSecret: "wrong"}); !errors.Is(err, ErrInvalidClient) {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := f.svc.AuthenticateClient(ctx, ClientAuthInput{ClientID: "conf", ClientSecret: ""}); !errors.Is(err, ErrInvalidClient) {
		t.Errorf("missing secret: %v", err)
	}
}

func TestAuthenticateClient_PublicRejectsSecret(t *testing.T) {
	f := newFixture()
	c := &client.Client{ClientID: "pub"}
	f.clients.byClientID["pub"] = c

	if _, err := f.svc.AuthenticateClient(ctx, ClientAuthInput{ClientID: "pub"}); err != nil {
		t.Fatalf("public: %v", err)
	}
	if _, err := f.svc.AuthenticateClient(ctx, ClientAuthInput{ClientID: "pub", ClientSecret: "x"}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("public w/ secret: %v", err)
	}
}

func TestAuthenticateClient_Unknown(t *testing.T) {
	f := newFixture()
	if _, err := f.svc.AuthenticateClient(ctx, ClientAuthInput{ClientID: "ghost"}); !errors.Is(err, ErrInvalidClient) {
		t.Fatal(err)
	}
	if _, err := f.svc.AuthenticateClient(ctx, ClientAuthInput{}); !errors.Is(err, ErrInvalidClient) {
		t.Fatal(err)
	}
}

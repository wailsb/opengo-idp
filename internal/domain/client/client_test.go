package client

import (
	"errors"
	"testing"
)

func TestNewClient_Confidential(t *testing.T) {
	c, secret, err := NewClient(" API ", nil, []string{GrantTypeClientCredentials}, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "API" || c.ClientID == "" || secret == "" || c.ClientSecretHash == secret {
		t.Fatalf("unexpected client: %+v", c)
	}
	if !c.VerifySecret(secret) || c.VerifySecret("wrong") {
		t.Error("secret verification broken")
	}
}

func TestNewClient_Public(t *testing.T) {
	uris := []string{"https://app.example.com/cb"}
	c, secret, err := NewClient("SPA", uris, []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken}, false)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || c.ClientSecretHash != "" || c.VerifySecret("") {
		t.Error("public client must have no usable secret")
	}

	uris[0] = "https://mutated.example.com"
	if c.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Error("redirect URIs must be copied, not aliased")
	}
	if !c.IsRedirectURIAllowed("https://app.example.com/cb") || c.IsRedirectURIAllowed("https://app.example.com/cb/extra") {
		t.Error("redirect matching must be exact")
	}
	if !c.IsGrantTypeAllowed(GrantTypeRefreshToken) || c.IsGrantTypeAllowed(GrantTypeClientCredentials) {
		t.Error("grant type check broken")
	}
}

func TestNewClient_Validation(t *testing.T) {
	cases := map[string]struct {
		name    string
		uris    []string
		grants  []string
		conf    bool
		wantErr error
	}{
		"empty name":           {"  ", nil, nil, false, ErrInvalidClientName},
		"unsupported grant":    {"x", nil, []string{"password"}, true, ErrUnsupportedGrantType},
		"public client creds":  {"x", nil, []string{GrantTypeClientCredentials}, false, ErrPublicClientGrant},
		"authcode without uri": {"x", nil, []string{GrantTypeAuthorizationCode}, false, ErrMissingRedirectURI},
		"relative uri":         {"x", []string{"/cb"}, []string{GrantTypeAuthorizationCode}, false, ErrInvalidRedirectURI},
		"fragment uri":         {"x", []string{"https://a.com/cb#x"}, []string{GrantTypeAuthorizationCode}, false, ErrInvalidRedirectURI},
		"empty fragment uri":   {"x", []string{"https://a.com/cb#"}, []string{GrantTypeAuthorizationCode}, false, ErrInvalidRedirectURI},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NewClient(tc.name, tc.uris, tc.grants, tc.conf); !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

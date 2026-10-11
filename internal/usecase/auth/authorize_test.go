package auth

import (
	"errors"
	"testing"

	"github.com/wailsb/opengo-idp/internal/domain/authcode"
	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/token"
)

// authCodeClient installs a client suitable for the auth-code flow in the fixture.
func authCodeClient(f *fixture, confidential bool) *client.Client {
	c := &client.Client{
		ID:                f.clients.byClientID["web-app"].ID,
		ClientID:          "spa",
		Name:              "SPA",
		RedirectURIs:      []string{"https://app.test/cb"},
		AllowedGrantTypes: []string{client.GrantTypeAuthorizationCode, client.GrantTypeRefreshToken},
		IsConfidential:    confidential,
	}
	f.clients.byClientID["spa"] = c
	return c
}

func TestIssueAuthCode_PersistsCode(t *testing.T) {
	f := newFixture()
	c := authCodeClient(f, false)
	out := login(t, f)

	code, err := f.svc.IssueAuthCode(ctx, IssueAuthCodeInput{
		Client:              c,
		UserID:              f.alice.ID,
		SessionID:           out.Session.ID,
		RedirectURI:         "https://app.test/cb",
		Scopes:              []string{token.ScopeOpenID, token.ScopeOfflineAccess},
		Nonce:               "n1",
		CodeChallenge:       ComputeS256Challenge("verifier"),
		CodeChallengeMethod: authcode.ChallengeMethodS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code.Code == "" {
		t.Error("empty code")
	}
	if _, ok := f.authCodes.byCode[code.Code]; !ok {
		t.Error("code was not persisted")
	}
}

func TestIssueAuthCode_RejectsBadRedirect(t *testing.T) {
	f := newFixture()
	c := authCodeClient(f, false)
	_, err := f.svc.IssueAuthCode(ctx, IssueAuthCodeInput{
		Client:      c,
		UserID:      f.alice.ID,
		RedirectURI: "https://evil.test/cb",
		Scopes:      []string{token.ScopeOpenID},
	})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("got %v, want ErrInvalidGrant", err)
	}
}

func TestIssueAuthCode_RejectsWrongGrant(t *testing.T) {
	f := newFixture()
	c := authCodeClient(f, false)
	c.AllowedGrantTypes = []string{client.GrantTypeRefreshToken} // no code grant
	_, err := f.svc.IssueAuthCode(ctx, IssueAuthCodeInput{
		Client:      c,
		UserID:      f.alice.ID,
		RedirectURI: "https://app.test/cb",
	})
	if !errors.Is(err, ErrUnauthorizedClient) {
		t.Fatalf("got %v, want ErrUnauthorizedClient", err)
	}
}

func issueCodeFor(t *testing.T, f *fixture, c *client.Client, scopes []string, verifier string) *authcode.AuthCode {
	t.Helper()
	out := login(t, f)
	code, err := f.svc.IssueAuthCode(ctx, IssueAuthCodeInput{
		Client:              c,
		UserID:              f.alice.ID,
		SessionID:           out.Session.ID,
		RedirectURI:         "https://app.test/cb",
		Scopes:              scopes,
		Nonce:               "n1",
		CodeChallenge:       ComputeS256Challenge(verifier),
		CodeChallengeMethod: authcode.ChallengeMethodS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestAuthorizationCode_Success(t *testing.T) {
	f := newFixture()
	c := authCodeClient(f, false)
	code := issueCodeFor(t, f, c, []string{token.ScopeOpenID, token.ScopeOfflineAccess}, "verif")

	tp, err := f.svc.AuthorizationCode(ctx, AuthCodeGrantInput{
		Client:       c,
		Code:         code.Code,
		RedirectURI:  "https://app.test/cb",
		CodeVerifier: "verif",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tp.AccessToken == "" || tp.RefreshToken == "" || tp.IDToken == "" {
		t.Fatalf("missing tokens: %+v", tp)
	}
	if tp.Scope != "openid offline_access" {
		t.Errorf("scope = %q", tp.Scope)
	}

	// Code is single-use: a second attempt fails.
	if _, err := f.svc.AuthorizationCode(ctx, AuthCodeGrantInput{
		Client: c, Code: code.Code, RedirectURI: "https://app.test/cb", CodeVerifier: "verif",
	}); !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("reuse: got %v, want ErrInvalidGrant", err)
	}
}

func TestAuthorizationCode_NoRefreshWithoutOfflineAccess(t *testing.T) {
	f := newFixture()
	c := authCodeClient(f, false)
	code := issueCodeFor(t, f, c, []string{token.ScopeOpenID}, "verif")

	tp, err := f.svc.AuthorizationCode(ctx, AuthCodeGrantInput{
		Client: c, Code: code.Code, RedirectURI: "https://app.test/cb", CodeVerifier: "verif",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tp.RefreshToken != "" {
		t.Error("refresh token must only be issued when offline_access is requested")
	}
	if tp.IDToken == "" {
		t.Error("id token must be issued for openid scope")
	}
}

func TestAuthorizationCode_PKCEFailure(t *testing.T) {
	f := newFixture()
	c := authCodeClient(f, false)
	code := issueCodeFor(t, f, c, []string{token.ScopeOpenID}, "verif")

	cases := map[string]string{
		"wrong verifier": "wrong",
		"empty verifier": "",
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			// Re-issue because the previous call consumed it.
			code := issueCodeFor(t, f, c, []string{token.ScopeOpenID}, "verif")
			_, err := f.svc.AuthorizationCode(ctx, AuthCodeGrantInput{
				Client: c, Code: code.Code, RedirectURI: "https://app.test/cb", CodeVerifier: v,
			})
			if !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("got %v, want ErrInvalidGrant", err)
			}
		})
	}
	_ = code
}

func TestAuthorizationCode_RedirectURIMismatch(t *testing.T) {
	f := newFixture()
	c := authCodeClient(f, false)
	code := issueCodeFor(t, f, c, []string{token.ScopeOpenID}, "verif")

	_, err := f.svc.AuthorizationCode(ctx, AuthCodeGrantInput{
		Client: c, Code: code.Code, RedirectURI: "https://app.test/other", CodeVerifier: "verif",
	})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("got %v, want ErrInvalidGrant", err)
	}
}

func TestAuthorizationCode_CrossClientRevokesSession(t *testing.T) {
	f := newFixture()
	victim := authCodeClient(f, false)
	// Register an attacker client that will try to redeem the victim's code.
	attacker := &client.Client{
		ClientID:          "attacker",
		AllowedGrantTypes: []string{client.GrantTypeAuthorizationCode},
		RedirectURIs:      []string{"https://app.test/cb"},
	}
	f.clients.byClientID["attacker"] = attacker

	code := issueCodeFor(t, f, victim, []string{token.ScopeOpenID}, "verif")

	_, err := f.svc.AuthorizationCode(ctx, AuthCodeGrantInput{
		Client: attacker, Code: code.Code, RedirectURI: "https://app.test/cb", CodeVerifier: "verif",
	})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("got %v, want ErrInvalidGrant", err)
	}
	// Session the code belonged to must be revoked.
	if len(f.sessions.byID) != 0 {
		t.Errorf("session not revoked after cross-client misuse: %d sessions remain", len(f.sessions.byID))
	}
}

package httpapi

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/usecase/auth"
)

func TestToken_AuthCodeGrant_Success(t *testing.T) {
	a := &fakeAuth{authedClient: &client.Client{ClientID: "spa", IsConfidential: false}}
	h := newTestServer(a, &fakeVerifier{})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"the-code"},
		"redirect_uri":  {"https://app.test/cb"},
		"client_id":     {"spa"},
		"code_verifier": {"verif"},
	}
	rec, body := do(t, h, tokenReq(form))
	if rec.Code != 200 || body["access_token"] != "at" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
	if a.lastCodeInput.Code != "the-code" || a.lastCodeInput.RedirectURI != "https://app.test/cb" || a.lastCodeInput.CodeVerifier != "verif" {
		t.Errorf("input: %+v", a.lastCodeInput)
	}
	if a.lastClientAuth.ClientID != "spa" {
		t.Errorf("client auth: %+v", a.lastClientAuth)
	}
}

func TestToken_AuthCodeGrant_BasicAuth(t *testing.T) {
	a := &fakeAuth{authedClient: &client.Client{ClientID: "conf", IsConfidential: true}}
	h := newTestServer(a, &fakeVerifier{})

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"the-code"},
		"redirect_uri": {"https://app.test/cb"},
	}
	r := tokenReq(form)
	creds := base64.StdEncoding.EncodeToString([]byte("conf:s3cret"))
	r.Header.Set("Authorization", "Basic "+creds)
	rec, body := do(t, h, r)
	if rec.Code != 200 || body["access_token"] != "at" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
	if !a.lastClientAuth.PresentedBasic || a.lastClientAuth.ClientID != "conf" || a.lastClientAuth.ClientSecret != "s3cret" {
		t.Errorf("basic auth input: %+v", a.lastClientAuth)
	}
}

func TestToken_AuthCodeGrant_PublicRequiresVerifier(t *testing.T) {
	a := &fakeAuth{authedClient: &client.Client{ClientID: "spa", IsConfidential: false}}
	h := newTestServer(a, &fakeVerifier{})

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"the-code"},
		"redirect_uri": {"https://app.test/cb"},
		"client_id":    {"spa"},
	}
	rec, body := do(t, h, tokenReq(form))
	if rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
}

func TestToken_AuthCodeGrant_InvalidClient(t *testing.T) {
	a := &fakeAuth{clientAuthErr: auth.ErrInvalidClient}
	h := newTestServer(a, &fakeVerifier{})

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"c"},
		"redirect_uri": {"https://app.test/cb"},
		"client_id":    {"spa"},
	}
	rec, body := do(t, h, tokenReq(form))
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
}

func TestToken_AuthCodeGrant_InvalidGrant(t *testing.T) {
	a := &fakeAuth{
		authedClient: &client.Client{ClientID: "spa"},
		codeGrantErr: auth.ErrInvalidGrant,
	}
	h := newTestServer(a, &fakeVerifier{})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"c"},
		"redirect_uri":  {"https://app.test/cb"},
		"client_id":     {"spa"},
		"code_verifier": {"v"},
	}
	rec, body := do(t, h, tokenReq(form))
	if rec.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
}

func TestToken_ClientCredentials_Success(t *testing.T) {
	a := &fakeAuth{authedClient: &client.Client{ClientID: "api", IsConfidential: true}}
	h := newTestServer(a, &fakeVerifier{})

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"scope":         {"profile openid"},
		"client_id":     {"api"},
		"client_secret": {"s"},
	}
	rec, body := do(t, h, tokenReq(form))
	if rec.Code != 200 || body["access_token"] != "cc" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
	if body["refresh_token"] != nil {
		t.Error("client_credentials must not include refresh_token")
	}
	// Only supported scopes forwarded.
	wantScopes := map[string]bool{"profile": false, "openid": false}
	for _, s := range a.lastCCInput.Scopes {
		wantScopes[s] = true
	}
	if !wantScopes["profile"] || !wantScopes["openid"] {
		t.Errorf("scopes forwarded: %v", a.lastCCInput.Scopes)
	}
}

func TestToken_ClientCredentials_RequiresCreds(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	rec, body := do(t, h, tokenReq(url.Values{"grant_type": {"client_credentials"}}))
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
}

func TestToken_BasicAndFormMutuallyExclusive(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"api"},
		"client_secret": {"s"},
	}
	r := tokenReq(form)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("api:s")))

	rec, body := do(t, h, r)
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
}

func TestResolveClientAuth_BasicDecoding(t *testing.T) {
	// Smoke test the URL-decoding path mandated by RFC 6749 §2.3.1.
	r := httptest.NewRequest("POST", "/token", strings.NewReader(""))
	raw := base64.StdEncoding.EncodeToString([]byte("my%20client:p%40ss"))
	r.Header.Set("Authorization", "Basic "+raw)
	_ = r.ParseForm()
	in, ok := resolveClientAuth(r)
	if !ok || in.ClientID != "my client" || in.ClientSecret != "p@ss" {
		t.Fatalf("got %+v ok=%v", in, ok)
	}
}

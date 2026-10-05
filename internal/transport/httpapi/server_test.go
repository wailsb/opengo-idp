package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/usecase/auth"
)

type fakeAuth struct {
	loginErr   error
	refreshErr error
	logoutErr  error
	lastLogin  auth.LoginInput
	loggedOut  []string
}

var testTokens = &auth.TokenPair{AccessToken: "at", RefreshToken: "rt", TokenType: "Bearer", ExpiresIn: 900}

func (f *fakeAuth) Login(_ context.Context, in auth.LoginInput) (*auth.LoginOutput, error) {
	f.lastLogin = in
	if f.loginErr != nil {
		return nil, f.loginErr
	}
	return &auth.LoginOutput{
		Session: &session.Session{ID: "sid-123", ExpiresAt: time.Now().Add(time.Hour)},
		Tokens:  testTokens,
	}, nil
}

func (f *fakeAuth) Refresh(_ context.Context, in auth.RefreshInput) (*auth.TokenPair, error) {
	if f.refreshErr != nil {
		return nil, f.refreshErr
	}
	return testTokens, nil
}

func (f *fakeAuth) Logout(_ context.Context, id string) error {
	f.loggedOut = append(f.loggedOut, id)
	return f.logoutErr
}

type fakeVerifier struct{ panicOnJWKS bool }

var testSubject = uuid.New()

func (f *fakeVerifier) ValidateToken(tok string) (*token.AccessTokenClaims, error) {
	if tok != "good" {
		return nil, token.ErrInvalidToken
	}
	c := &token.AccessTokenClaims{Email: "a@example.com", Roles: []string{"admin"}}
	c.Subject = testSubject.String()
	return c, nil
}

func (f *fakeVerifier) GetJWKS(context.Context) (map[string]interface{}, error) {
	if f.panicOnJWKS {
		panic("boom")
	}
	return map[string]interface{}{"keys": []any{map[string]string{"kid": "k1"}}}, nil
}

func newTestServer(a *fakeAuth, v *fakeVerifier) http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(a, v, Config{Issuer: "https://idp.test/", SecureCookies: true}, log).Handler()
}

func do(t *testing.T, h http.Handler, req *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("non-JSON body %q: %v", rec.Body.String(), err)
		}
	}
	return rec, body
}

func TestHealthAndDiscovery(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	rec, body := do(t, h, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || body["status"] != "ok" {
		t.Errorf("healthz: %d %v", rec.Code, body)
	}

	rec, body = do(t, h, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if rec.Code != 200 {
		t.Fatalf("discovery: %d", rec.Code)
	}
	// Trailing slash on the configured issuer must not leak into URLs.
	if body["issuer"] != "https://idp.test" || body["jwks_uri"] != "https://idp.test/.well-known/jwks.json" {
		t.Errorf("discovery urls: %v", body)
	}
}

func TestJWKS(t *testing.T) {
	rec, body := do(t, newTestServer(&fakeAuth{}, &fakeVerifier{}), httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rec.Code != 200 || body["keys"] == nil {
		t.Fatalf("jwks: %d %v", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Error("jwks should be cacheable")
	}
}

func TestPanicRecovery(t *testing.T) {
	rec, body := do(t, newTestServer(&fakeAuth{}, &fakeVerifier{panicOnJWKS: true}), httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rec.Code != 500 || body["error"] != "server_error" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
}

func loginReq(body string) *http.Request {
	r := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "test-ua")
	r.RemoteAddr = "203.0.113.7:5555"
	return r
}

func TestLogin_Success(t *testing.T) {
	a := &fakeAuth{}
	rec, body := do(t, newTestServer(a, &fakeVerifier{}), loginReq(`{"identifier":"alice","password":"pw","client_id":"web","nonce":"n"}`))
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["access_token"] != "at" || body["refresh_token"] != "rt" || body["token_type"] != "Bearer" || body["expires_in"] != float64(900) {
		t.Errorf("body: %v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("token response must not be cached")
	}

	if a.lastLogin.IPAddress != "203.0.113.7" || a.lastLogin.UserAgent != "test-ua" || a.lastLogin.ClientID != "web" || a.lastLogin.Nonce != "n" {
		t.Errorf("login input: %+v", a.lastLogin)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName || c.Value != "sid-123" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes: %+v", c)
	}
}

func TestLogin_Errors(t *testing.T) {
	cases := map[string]struct {
		body     string
		err      error
		wantCode int
		wantErr  string
	}{
		"malformed json":   {`{`, nil, 400, "invalid_request"},
		"unknown field":    {`{"identifier":"a","password":"b","admin":true}`, nil, 400, "invalid_request"},
		"missing password": {`{"identifier":"a"}`, nil, 400, "invalid_request"},
		"bad credentials":  {`{"identifier":"a","password":"b"}`, auth.ErrInvalidCredentials, 401, "invalid_credentials"},
		"disabled":         {`{"identifier":"a","password":"b"}`, auth.ErrUserInactive, 403, "user_disabled"},
		"unknown client":   {`{"identifier":"a","password":"b","client_id":"x"}`, auth.ErrInvalidClient, 400, "invalid_client"},
		"internal failure": {`{"identifier":"a","password":"b"}`, errors.New("db down"), 500, "server_error"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec, body := do(t, newTestServer(&fakeAuth{loginErr: tc.err}, &fakeVerifier{}), loginReq(tc.body))
			if rec.Code != tc.wantCode || body["error"] != tc.wantErr {
				t.Fatalf("got %d %v, want %d %s", rec.Code, body, tc.wantCode, tc.wantErr)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Error("no cookie must be set on failure")
			}
			if tc.err != nil && strings.Contains(rec.Body.String(), tc.err.Error()) && tc.wantCode == 500 {
				t.Error("internal error details leaked to client")
			}
		})
	}
}

func TestLogout(t *testing.T) {
	a := &fakeAuth{}
	h := newTestServer(a, &fakeVerifier{})

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sid-123"})
	rec, _ := do(t, h, req)
	if rec.Code != 204 {
		t.Fatalf("status %d", rec.Code)
	}
	if len(a.loggedOut) != 1 || a.loggedOut[0] != "sid-123" {
		t.Errorf("logged out: %v", a.loggedOut)
	}
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Errorf("cookie not cleared: %+v", c)
	}

	// Without a cookie it is still a successful no-op.
	rec, _ = do(t, h, httptest.NewRequest("POST", "/logout", nil))
	if rec.Code != 204 || len(a.loggedOut) != 1 {
		t.Errorf("no-cookie logout: %d %v", rec.Code, a.loggedOut)
	}
}

func tokenReq(form url.Values) *http.Request {
	r := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestToken_Refresh(t *testing.T) {
	rec, body := do(t, newTestServer(&fakeAuth{}, &fakeVerifier{}),
		tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt"}}))
	if rec.Code != 200 || body["access_token"] != "at" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing Cache-Control: no-store")
	}
}

func TestToken_Errors(t *testing.T) {
	cases := map[string]struct {
		form     url.Values
		err      error
		wantCode int
		wantErr  string
	}{
		"missing grant":     {url.Values{}, nil, 400, "invalid_request"},
		"unsupported grant": {url.Values{"grant_type": {"password"}}, nil, 400, "unsupported_grant_type"},
		"missing token":     {url.Values{"grant_type": {"refresh_token"}}, nil, 400, "invalid_request"},
		"invalid grant":     {url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, auth.ErrInvalidGrant, 400, "invalid_grant"},
		"invalid client":    {url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {"c"}}, auth.ErrInvalidClient, 401, "invalid_client"},
		"internal":          {url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, errors.New("boom"), 500, "server_error"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec, body := do(t, newTestServer(&fakeAuth{refreshErr: tc.err}, &fakeVerifier{}), tokenReq(tc.form))
			if rec.Code != tc.wantCode || body["error"] != tc.wantErr {
				t.Fatalf("got %d %v, want %d %s", rec.Code, body, tc.wantCode, tc.wantErr)
			}
		})
	}
}

func TestUserInfo(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec, body := do(t, h, req)
	if rec.Code != 200 || body["sub"] != testSubject.String() || body["email"] != "a@example.com" {
		t.Fatalf("got %d %v", rec.Code, body)
	}

	for name, header := range map[string]string{
		"missing":    "",
		"bad token":  "Bearer bad",
		"wrong type": "Basic abc",
		"empty":      "Bearer ",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/userinfo", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec, body := do(t, h, req)
			if rec.Code != 401 || body["error"] != "invalid_token" {
				t.Fatalf("got %d %v", rec.Code, body)
			}
			if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Error("missing WWW-Authenticate challenge")
			}
		})
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(&fakeAuth{}, &fakeVerifier{}).ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wailsb/opengo-idp/internal/domain/client"
)

func authorizeReq(q url.Values, sessionCookie string) *http.Request {
	r := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	if sessionCookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionCookie})
	}
	return r
}

func publicClient() *client.Client {
	return &client.Client{
		ClientID:          "spa",
		RedirectURIs:      []string{"https://app.test/cb"},
		AllowedGrantTypes: []string{client.GrantTypeAuthorizationCode},
	}
}

func TestAuthorize_RedirectsToLoginWhenUnauthenticated(t *testing.T) {
	a := &fakeAuth{validateErr: errSessionNotFound{}}
	h := newTestServerWithClients(a, &fakeVerifier{}, map[string]*client.Client{
		"spa": publicClient(),
	})

	q := url.Values{
		"client_id":             {"spa"},
		"redirect_uri":          {"https://app.test/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authorizeReq(q, ""))
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("location = %q, want /login", loc)
	}
	// Return cookie was set.
	var saw bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == loginReturnCookie && strings.Contains(c.Value, "/authorize") {
			saw = true
		}
	}
	if !saw {
		t.Error("missing or empty return cookie")
	}
}

type errSessionNotFound struct{}

func (errSessionNotFound) Error() string { return "not found" }

func TestAuthorize_IssuesCodeAndRedirects(t *testing.T) {
	a := &fakeAuth{issuedCode: "the-code"}
	h := newTestServerWithClients(a, &fakeVerifier{}, map[string]*client.Client{
		"spa": publicClient(),
	})

	q := url.Values{
		"client_id":             {"spa"},
		"redirect_uri":          {"https://app.test/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"state-value"},
		"nonce":                 {"n0nce"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authorizeReq(q, "sid-123"))

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "app.test" || loc.Path != "/cb" {
		t.Errorf("redirect host/path: %v", loc)
	}
	if loc.Query().Get("code") != "the-code" || loc.Query().Get("state") != "state-value" {
		t.Errorf("redirect query: %v", loc.RawQuery)
	}
	if a.lastIssueCodeIn.Nonce != "n0nce" || a.lastIssueCodeIn.CodeChallenge != "challenge" {
		t.Errorf("issue input: %+v", a.lastIssueCodeIn)
	}
}

func TestAuthorize_RejectsBadClientWithHTMLError(t *testing.T) {
	h := newTestServerWithClients(&fakeAuth{}, &fakeVerifier{}, nil)

	q := url.Values{
		"client_id":    {"ghost"},
		"redirect_uri": {"https://app.test/cb"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authorizeReq(q, ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Error("expected HTML error page")
	}
}

func TestAuthorize_RejectsBadRedirectURIWithHTMLError(t *testing.T) {
	h := newTestServerWithClients(&fakeAuth{}, &fakeVerifier{}, map[string]*client.Client{
		"spa": publicClient(),
	})
	q := url.Values{
		"client_id":    {"spa"},
		"redirect_uri": {"https://evil.test/cb"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authorizeReq(q, ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	// Must NOT redirect anywhere.
	if rec.Header().Get("Location") != "" {
		t.Error("must not redirect to an unregistered URI")
	}
}

func TestAuthorize_PublicClientRequiresPKCE(t *testing.T) {
	h := newTestServerWithClients(&fakeAuth{}, &fakeVerifier{}, map[string]*client.Client{
		"spa": publicClient(),
	})
	q := url.Values{
		"client_id":     {"spa"},
		"redirect_uri":  {"https://app.test/cb"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authorizeReq(q, "sid"))

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("want invalid_request, got %v", loc.Query())
	}
}

func TestAuthorize_RedirectsErrorWhenScopeMissingOpenID(t *testing.T) {
	h := newTestServerWithClients(&fakeAuth{}, &fakeVerifier{}, map[string]*client.Client{
		"spa": publicClient(),
	})
	q := url.Values{
		"client_id":             {"spa"},
		"redirect_uri":          {"https://app.test/cb"},
		"response_type":         {"code"},
		"scope":                 {"profile"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authorizeReq(q, "sid"))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_scope" || loc.Query().Get("state") != "s" {
		t.Errorf("got %v", loc.Query())
	}
}

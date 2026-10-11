package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLoginHTML_GET_RendersForm(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))

	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Error("want HTML content type")
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Error("response did not contain a form")
	}

	var csrf string
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookie {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Error("csrf cookie missing")
	}
	if !strings.Contains(rec.Body.String(), csrf) {
		t.Error("csrf token not rendered in form")
	}
}

func formRequestWithCSRF(form url.Values, csrfVal string) *http.Request {
	form.Set("csrf_token", csrfVal)
	r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrfVal})
	return r
}

func TestLoginHTML_POST_SuccessRedirects(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	form := url.Values{"identifier": {"alice"}, "password": {"pw"}, "return_to": {"/authorize?x=1"}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, formRequestWithCSRF(form, "csrf-value"))

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "/authorize?x=1" {
		t.Errorf("location = %q", rec.Header().Get("Location"))
	}
	var saw bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value == "sid-123" {
			saw = true
		}
	}
	if !saw {
		t.Error("session cookie not set")
	}
}

func TestLoginHTML_POST_RejectsOpenRedirect(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	form := url.Values{"identifier": {"alice"}, "password": {"pw"}, "return_to": {"https://evil.test/"}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, formRequestWithCSRF(form, "csrf"))

	if rec.Header().Get("Location") == "https://evil.test/" {
		t.Fatal("open redirect accepted")
	}
}

func TestLoginHTML_POST_CSRFMismatch(t *testing.T) {
	h := newTestServer(&fakeAuth{}, &fakeVerifier{})

	r := httptest.NewRequest("POST", "/login",
		strings.NewReader(url.Values{"identifier": {"a"}, "password": {"b"}, "csrf_token": {"form"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "cookie"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

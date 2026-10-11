package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/wailsb/opengo-idp/internal/domain/authcode"
	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/transport/httpapi/templates"
	"github.com/wailsb/opengo-idp/internal/usecase/auth"
)

// loginReturnCookie carries the full /authorize URL across the login redirect.
// Lax so the browser sends it back on the top-level POST that completes login.
const loginReturnCookie = "idp_login_return"

// handleAuthorize implements the authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1).
// Errors before the redirect_uri is validated render an HTML error page. Errors
// after that validation are redirected back to the client with ?error=....
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if clientID == "" {
		s.renderAuthorizeError(w, "invalid_request", "client_id is required")
		return
	}
	c, err := s.clients.GetByClientID(r.Context(), clientID)
	if errors.Is(err, client.ErrClientNotFound) {
		s.renderAuthorizeError(w, "invalid_client", "unknown client")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}

	if redirectURI == "" {
		s.renderAuthorizeError(w, "invalid_request", "redirect_uri is required")
		return
	}
	if !c.IsRedirectURIAllowed(redirectURI) {
		s.renderAuthorizeError(w, "invalid_redirect_uri", "redirect_uri is not registered for this client")
		return
	}

	// From here on, errors are reported by redirecting back to the client with
	// error, error_description, state query parameters.
	fail := func(code, desc string) {
		redirectWithError(w, r, redirectURI, code, desc, state)
	}

	if !c.IsGrantTypeAllowed(client.GrantTypeAuthorizationCode) {
		fail("unauthorized_client", "client is not allowed to use the authorization_code grant")
		return
	}
	if responseType != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}

	scopes := token.ParseScopes(scope)
	if !token.HasScope(scopes, token.ScopeOpenID) {
		fail("invalid_scope", "the openid scope is required")
		return
	}

	// PKCE: mandatory for public clients, recommended for confidential.
	if codeChallenge == "" && !c.IsConfidential {
		fail("invalid_request", "code_challenge is required for public clients")
		return
	}
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = authcode.ChallengeMethodS256
		}
		if codeChallengeMethod != authcode.ChallengeMethodS256 {
			// S256 only (OAuth 2.1 drops "plain").
			fail("invalid_request", "only S256 code_challenge_method is supported")
			return
		}
	}

	// If no valid session cookie, bounce to the HTML login then come back here.
	sessionID := sessionIDFromCookie(r)
	sess, err := s.auth.ValidateSession(r.Context(), sessionID)
	if err != nil || sess == nil {
		s.redirectToLogin(w, r)
		return
	}

	// TODO(phase1 item 9): consent screen. For now auto-approve.

	code, err := s.auth.IssueAuthCode(r.Context(), auth.IssueAuthCodeInput{
		Client:              c,
		UserID:              sess.UserID,
		SessionID:           sess.ID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "issue auth code", "err", err)
		fail("server_error", "could not issue authorization code")
		return
	}

	redirectWithCode(w, r, redirectURI, code.Code, state)
}

func redirectWithCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, code, desc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) renderAuthorizeError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = templates.Error.Execute(w, templates.ErrorData{Code: code, Description: desc})
}

// sessionIDFromCookie returns the SSO session ID from the cookie, or "" if absent.
func sessionIDFromCookie(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

// redirectToLogin stores the current /authorize URL in a short-lived cookie and
// redirects the user agent to the login page.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Only accept same-host return URLs to prevent being used as an open redirector.
	returnTo := r.URL.RequestURI()
	http.SetCookie(w, &http.Cookie{
		Name:     loginReturnCookie,
		Value:    returnTo,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// newCSRFToken returns a 128-bit URL-safe random token for the double-submit cookie.
func newCSRFToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// safeReturnTo validates that a return_to URL is a path on this server (no scheme,
// no host), so the login flow cannot be abused as an open redirect.
func safeReturnTo(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	if _, err := url.Parse(raw); err != nil {
		return ""
	}
	return raw
}

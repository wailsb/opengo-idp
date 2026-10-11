package httpapi

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/wailsb/opengo-idp/internal/transport/httpapi/templates"
	"github.com/wailsb/opengo-idp/internal/usecase/auth"
)

// csrfCookie carries the server-generated token for double-submit CSRF. Content
// comparison with the form value is constant-time.
const csrfCookie = "idp_csrf"

// handleLoginGET renders the HTML login form, (re)setting a CSRF cookie.
func (s *Server) handleLoginGET(w http.ResponseWriter, r *http.Request) {
	returnTo := safeReturnTo(returnToFromCookie(r))
	token := newCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = templates.Login.Execute(w, templates.LoginData{
		CSRFToken: token,
		ReturnTo:  returnTo,
	})
}

// handleLoginPOST processes the HTML form submission. It accepts form-encoded
// bodies only; JSON callers go to /api/login.
func (s *Server) handleLoginPOST(w http.ResponseWriter, r *http.Request) {
	// Content-Type gate so this handler can't be targeted by JSON callers that
	// expected /api/login.
	ct := r.Header.Get("Content-Type")
	if ct != "" && !isFormContentType(ct) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "expected application/x-www-form-urlencoded")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	// Double-submit CSRF: form value must equal cookie value.
	cookie, err := r.Cookie(csrfCookie)
	formToken := r.PostForm.Get("csrf_token")
	if err != nil || cookie.Value == "" || formToken == "" ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) != 1 {
		s.renderLoginError(w, "csrf verification failed", "", "")
		return
	}

	identifier := r.PostForm.Get("identifier")
	password := r.PostForm.Get("password")
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))

	if identifier == "" || password == "" {
		s.renderLoginError(w, "identifier and password are required", identifier, returnTo)
		return
	}

	out, err := s.auth.Login(r.Context(), auth.LoginInput{
		Identifier: identifier,
		Password:   password,
		IPAddress:  clientIP(r),
		UserAgent:  r.UserAgent(),
	})
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.renderLoginError(w, "invalid identifier or password", identifier, returnTo)
		return
	case errors.Is(err, auth.ErrUserInactive):
		s.renderLoginError(w, "user account is disabled", identifier, returnTo)
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    out.Session.ID,
		Path:     "/",
		Expires:  out.Session.ExpiresAt,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	// Clear the stashed return cookie now that we have consumed it.
	clearCookie(w, loginReturnCookie, s.cfg.SecureCookies)

	// Default to a bland success page if no return URL was supplied.
	target := returnTo
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) renderLoginError(w http.ResponseWriter, msg, identifier, returnTo string) {
	// Re-issue the CSRF token on error so the user can retry.
	token := newCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = templates.Login.Execute(w, templates.LoginData{
		CSRFToken:  token,
		Identifier: identifier,
		ReturnTo:   returnTo,
		Error:      msg,
	})
}

func returnToFromCookie(r *http.Request) string {
	c, err := r.Cookie(loginReturnCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func isFormContentType(ct string) bool {
	// Match either "application/x-www-form-urlencoded" or "...;charset=utf-8".
	for i := 0; i < len(ct); i++ {
		if ct[i] == ';' {
			ct = ct[:i]
			break
		}
	}
	return ct == "application/x-www-form-urlencoded"
}

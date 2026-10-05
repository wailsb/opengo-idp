package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/wailsb/opengo-idp/internal/usecase/auth"
)

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	ClientID   string `json:"client_id,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
}

// tokenResponse follows RFC 6749 §5.1.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func newTokenResponse(tp *auth.TokenPair) tokenResponse {
	return tokenResponse{
		AccessToken:  tp.AccessToken,
		TokenType:    tp.TokenType,
		ExpiresIn:    tp.ExpiresIn,
		RefreshToken: tp.RefreshToken,
		IDToken:      tp.IDToken,
	}
}

// handleLogin authenticates with JSON credentials, sets the SSO session cookie and
// returns tokens.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.Identifier == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "identifier and password are required")
		return
	}

	out, err := s.auth.Login(r.Context(), auth.LoginInput{
		Identifier: req.Identifier,
		Password:   req.Password,
		IPAddress:  clientIP(r),
		UserAgent:  r.UserAgent(),
		ClientID:   req.ClientID,
		Nonce:      req.Nonce,
	})
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid identifier or password")
		return
	case errors.Is(err, auth.ErrUserInactive):
		writeError(w, http.StatusForbidden, "user_disabled", "user account is disabled")
		return
	case errors.Is(err, auth.ErrInvalidClient):
		writeError(w, http.StatusBadRequest, "invalid_client", "unknown client")
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
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, newTokenResponse(out.Tokens))
}

// handleLogout ends the SSO session named by the cookie. It is idempotent: a missing
// or unknown cookie still clears the cookie and returns 204.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		if err := s.auth.Logout(r.Context(), c.Value); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleToken is the OAuth2 token endpoint (RFC 6749 §3.2). Only the refresh_token
// grant is implemented so far.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	switch grant := r.PostForm.Get("grant_type"); grant {
	case "refresh_token":
		s.refreshGrant(w, r)
	case "":
		writeError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

func (s *Server) refreshGrant(w http.ResponseWriter, r *http.Request) {
	refresh := r.PostForm.Get("refresh_token")
	if refresh == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	tp, err := s.auth.Refresh(r.Context(), auth.RefreshInput{
		RefreshToken: refresh,
		ClientID:     r.PostForm.Get("client_id"),
	})
	switch {
	case errors.Is(err, auth.ErrInvalidGrant):
		writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	case errors.Is(err, auth.ErrInvalidClient):
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newTokenResponse(tp))
}

// handleUserInfo returns claims about the bearer of a valid access token (OIDC Core §5.3).
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	raw, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}
	claims, err := s.tokens.ValidateToken(raw)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sub":         claims.Subject,
		"email":       claims.Email,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
	})
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" {
		return "", false
	}
	return strings.TrimSpace(tok), true
}

// clientIP uses the TCP peer address. X-Forwarded-For is deliberately ignored until
// trusted-proxy configuration exists, since any client can forge it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

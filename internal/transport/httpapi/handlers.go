package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/wailsb/opengo-idp/internal/domain/token"
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
	Scope        string `json:"scope,omitempty"`
}

func newTokenResponse(tp *auth.TokenPair) tokenResponse {
	return tokenResponse{
		AccessToken:  tp.AccessToken,
		TokenType:    tp.TokenType,
		ExpiresIn:    tp.ExpiresIn,
		RefreshToken: tp.RefreshToken,
		IDToken:      tp.IDToken,
		Scope:        tp.Scope,
	}
}

// handleAPILogin authenticates with JSON credentials, sets the SSO session cookie
// and returns tokens. This is the first-party / SPA entry point; browser flows go
// through the HTML form at /login.
func (s *Server) handleAPILogin(w http.ResponseWriter, r *http.Request) {
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

// handleToken is the OAuth2 token endpoint (RFC 6749 §3.2). Supported grants:
// refresh_token, authorization_code, client_credentials.
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
	case "authorization_code":
		s.authorizationCodeGrant(w, r)
	case "client_credentials":
		s.clientCredentialsGrant(w, r)
	case "":
		writeError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

// resolveClientAuth parses client credentials from either HTTP Basic (§2.3.1) or
// the request body (§2.3.2). Only one method may be used per request.
func resolveClientAuth(r *http.Request) (auth.ClientAuthInput, bool) {
	basicID, basicSecret, hasBasic := basicClientCreds(r)
	formID := r.PostForm.Get("client_id")
	formSecret := r.PostForm.Get("client_secret")

	if hasBasic {
		// Reject mixed methods (RFC 6749 §2.3): once Basic is used, no form creds.
		if formID != "" || formSecret != "" {
			return auth.ClientAuthInput{}, false
		}
		return auth.ClientAuthInput{ClientID: basicID, ClientSecret: basicSecret, PresentedBasic: true}, true
	}
	if formID == "" {
		return auth.ClientAuthInput{}, false
	}
	return auth.ClientAuthInput{ClientID: formID, ClientSecret: formSecret}, true
}

func basicClientCreds(r *http.Request) (string, string, bool) {
	h := r.Header.Get("Authorization")
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") || rest == "" {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", "", false
	}
	id, secret, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", false
	}
	// RFC 6749 §2.3.1: application/x-www-form-urlencoded unescaping on each component.
	idDecoded, err := url.QueryUnescape(id)
	if err != nil {
		return "", "", false
	}
	secretDecoded, err := url.QueryUnescape(secret)
	if err != nil {
		return "", "", false
	}
	return idDecoded, secretDecoded, true
}

// writeClientAuthError emits invalid_client, with WWW-Authenticate Basic if the
// client used HTTP Basic (RFC 6749 §5.2).
func writeClientAuthError(w http.ResponseWriter, usedBasic bool) {
	if usedBasic {
		w.Header().Set("WWW-Authenticate", `Basic realm="idp"`)
	}
	writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
}

func (s *Server) refreshGrant(w http.ResponseWriter, r *http.Request) {
	refresh := r.PostForm.Get("refresh_token")
	if refresh == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Client authentication is optional for refresh if the token is not bound to
	// a client (first-party). If credentials are present we authenticate.
	authIn, hasCreds := resolveClientAuth(r)
	clientID := r.PostForm.Get("client_id")
	if hasCreds {
		c, err := s.auth.AuthenticateClient(r.Context(), authIn)
		if err != nil {
			writeClientAuthError(w, authIn.PresentedBasic)
			return
		}
		clientID = c.ClientID
	}

	tp, err := s.auth.Refresh(r.Context(), auth.RefreshInput{
		RefreshToken: refresh,
		ClientID:     clientID,
	})
	switch {
	case errors.Is(err, auth.ErrInvalidGrant):
		writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	case errors.Is(err, auth.ErrInvalidClient):
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	case errors.Is(err, auth.ErrUnauthorizedClient):
		writeError(w, http.StatusBadRequest, "unauthorized_client", "client not authorized for refresh_token")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newTokenResponse(tp))
}

func (s *Server) authorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	codeVerifier := r.PostForm.Get("code_verifier")
	if code == "" || redirectURI == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}

	authIn, ok := resolveClientAuth(r)
	if !ok {
		writeClientAuthError(w, false)
		return
	}
	c, err := s.auth.AuthenticateClient(r.Context(), authIn)
	if err != nil {
		writeClientAuthError(w, authIn.PresentedBasic)
		return
	}

	// Public client must supply code_verifier (PKCE mandatory).
	if !c.IsConfidential && codeVerifier == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required for public clients")
		return
	}

	tp, err := s.auth.AuthorizationCode(r.Context(), auth.AuthCodeGrantInput{
		Client:       c,
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
	})
	switch {
	case errors.Is(err, auth.ErrInvalidGrant):
		writeError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid, expired or redirect_uri does not match")
		return
	case errors.Is(err, auth.ErrUnauthorizedClient):
		writeError(w, http.StatusBadRequest, "unauthorized_client", "client not authorized for authorization_code")
		return
	case errors.Is(err, auth.ErrInvalidClient):
		writeClientAuthError(w, authIn.PresentedBasic)
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newTokenResponse(tp))
}

func (s *Server) clientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	authIn, ok := resolveClientAuth(r)
	if !ok {
		writeClientAuthError(w, false)
		return
	}
	c, err := s.auth.AuthenticateClient(r.Context(), authIn)
	if err != nil || c == nil {
		writeClientAuthError(w, authIn.PresentedBasic)
		return
	}

	scopes := token.ParseScopes(r.PostForm.Get("scope"))
	tp, err := s.auth.ClientCredentials(r.Context(), auth.ClientCredentialsInput{Client: c, Scopes: scopes})
	switch {
	case errors.Is(err, auth.ErrUnauthorizedClient):
		writeError(w, http.StatusBadRequest, "unauthorized_client", "client not authorized for client_credentials")
		return
	case errors.Is(err, auth.ErrInvalidClient):
		writeClientAuthError(w, authIn.PresentedBasic)
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newTokenResponse(tp))
}

// handleUserInfo returns claims about the bearer of a valid access token (OIDC Core §5.3).
// Fields are filtered by the token's scope claim.
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

	scopes := token.ParseScopes(claims.Scope)
	// Legacy / first-party tokens have no scope: return every field, as before.
	includeAll := len(scopes) == 0
	resp := map[string]interface{}{
		"sub": claims.Subject,
	}
	if includeAll || token.HasScope(scopes, token.ScopeEmail) {
		resp["email"] = claims.Email
	}
	if includeAll || token.HasScope(scopes, token.ScopeProfile) {
		resp["preferred_username"] = claims.Email // kept for backwards compat with first-party
		resp["roles"] = claims.Roles
		resp["permissions"] = claims.Permissions
	}
	if includeAll {
		resp["roles"] = claims.Roles
		resp["permissions"] = claims.Permissions
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
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

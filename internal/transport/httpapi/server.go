// Package httpapi exposes the auth usecases over HTTP.
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/wailsb/opengo-idp/internal/domain/authcode"
	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/usecase/auth"
)

const (
	SessionCookieName = "idp_session"
	maxBodyBytes      = 64 << 10
)

// AuthService is the subset of auth.Service used by the handlers.
type AuthService interface {
	Login(ctx context.Context, in auth.LoginInput) (*auth.LoginOutput, error)
	Refresh(ctx context.Context, in auth.RefreshInput) (*auth.TokenPair, error)
	Logout(ctx context.Context, sessionID string) error
	ValidateSession(ctx context.Context, sessionID string) (*session.Session, error)
	IssueAuthCode(ctx context.Context, in auth.IssueAuthCodeInput) (*authcode.AuthCode, error)
	AuthorizationCode(ctx context.Context, in auth.AuthCodeGrantInput) (*auth.TokenPair, error)
	ClientCredentials(ctx context.Context, in auth.ClientCredentialsInput) (*auth.TokenPair, error)
	AuthenticateClient(ctx context.Context, in auth.ClientAuthInput) (*client.Client, error)
}

// ClientLookup is the subset of client.Repository used by /authorize to resolve
// the client before any auth happens.
type ClientLookup interface {
	GetByClientID(ctx context.Context, clientID string) (*client.Client, error)
}

// TokenVerifier is the subset of token.Service used by the handlers.
type TokenVerifier interface {
	ValidateToken(tokenStr string) (*token.AccessTokenClaims, error)
	GetJWKS(ctx context.Context) (map[string]interface{}, error)
}

type Config struct {
	Issuer string
	// SecureCookies sets the Secure flag; only disable for plain-HTTP local development.
	SecureCookies bool
}

type Server struct {
	auth    AuthService
	tokens  TokenVerifier
	clients ClientLookup
	cfg     Config
	log     *slog.Logger
}

func NewServer(a AuthService, t TokenVerifier, c ClientLookup, cfg Config, log *slog.Logger) *Server {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	return &Server{auth: a, tokens: t, clients: c, cfg: cfg, log: log}
}

// Handler returns the routed handler wrapped in recovery and access logging.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	// HTML login (browser flow). JSON clients: /api/login.
	mux.HandleFunc("GET /login", s.handleLoginGET)
	mux.HandleFunc("POST /login", s.handleLoginPOST)
	mux.HandleFunc("POST /api/login", s.handleAPILogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /userinfo", s.handleUserInfo)
	return s.recoverer(s.accessLog(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.cfg.Issuer
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer":                                iss,
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"scopes_supported":                      token.SupportedScopes,
		"code_challenge_methods_supported":      []string{authcode.ChallengeMethodS256},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "azp", "at_hash",
			"email", "preferred_username", "nonce", "scope",
		},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.tokens.GetJWKS(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, jwks)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError uses the OAuth2 error body shape ({"error", "error_description"}) for
// every endpoint so clients handle one format.
func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.InfoContext(r.Context(), "http request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration", time.Since(start))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.ErrorContext(r.Context(), "panic", "value", v, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "server_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

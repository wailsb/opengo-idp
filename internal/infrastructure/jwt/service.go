package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/wailsb/opengo-idp/internal/domain/access"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// Config sets the issuer and lifetimes of issued tokens.
type Config struct {
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	IDTokenTTL      time.Duration
}

// Service signs tokens with RS256. It implements token.Service.
type Service struct {
	keys token.KeyProvider
	cfg  Config
	now  func() time.Time
}

var _ token.Service = (*Service)(nil)

func NewService(keys token.KeyProvider, cfg Config) (*Service, error) {
	if _, ok := keys.GetPrivateKey().(*rsa.PrivateKey); !ok {
		return nil, errors.New("key provider must supply an *rsa.PrivateKey")
	}
	if _, ok := keys.GetPublicKey().(*rsa.PublicKey); !ok {
		return nil, errors.New("key provider must supply an *rsa.PublicKey")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("issuer must not be empty")
	}
	if cfg.AccessTokenTTL <= 0 || cfg.RefreshTokenTTL <= 0 || cfg.IDTokenTTL <= 0 {
		return nil, errors.New("token TTLs must be positive")
	}
	return &Service{keys: keys, cfg: cfg, now: time.Now}, nil
}

func (s *Service) registered(subject string, audience []string, ttl time.Duration) gojwt.RegisteredClaims {
	now := s.now().UTC()
	return gojwt.RegisteredClaims{
		Issuer:    s.cfg.Issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  gojwt.NewNumericDate(now),
		NotBefore: gojwt.NewNumericDate(now),
		ExpiresAt: gojwt.NewNumericDate(now.Add(ttl)),
		ID:        uuid.NewString(),
	}
}

func (s *Service) sign(claims gojwt.Claims) (string, error) {
	t := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	t.Header["kid"] = s.keys.GetKID()
	signed, err := t.SignedString(s.keys.GetPrivateKey())
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

func (s *Service) GenerateAccessToken(u *user.User, summary *access.UserAccessSummary) (string, error) {
	return s.GenerateAccessTokenFor(token.AccessTokenRequest{User: u, Summary: summary})
}

func (s *Service) GenerateAccessTokenFor(req token.AccessTokenRequest) (string, error) {
	if req.User == nil {
		return "", errors.New("access token requires a user")
	}
	claims := &token.AccessTokenClaims{
		RegisteredClaims: s.registered(req.User.ID.String(), req.Audience, s.cfg.AccessTokenTTL),
		TokenType:        token.TypeAccess,
		UserID:           req.User.ID,
		Email:            req.User.Email,
		Scope:            token.JoinScopes(req.Scopes),
		ClientID:         req.ClientID,
		AuthorizedTo:     req.ClientID,
	}
	if req.Summary != nil {
		claims.Roles = req.Summary.Roles
		claims.Permissions = req.Summary.Permissions
	}
	return s.sign(claims)
}

func (s *Service) GenerateRefreshToken(u *user.User, sessionID string) (string, error) {
	return s.GenerateRefreshTokenFor(token.RefreshTokenRequest{User: u, SessionID: sessionID})
}

func (s *Service) GenerateRefreshTokenFor(req token.RefreshTokenRequest) (string, error) {
	if req.User == nil {
		return "", errors.New("refresh token requires a user")
	}
	if req.SessionID == "" {
		return "", errors.New("refresh token requires a session ID")
	}
	return s.sign(&token.RefreshTokenClaims{
		RegisteredClaims: s.registered(req.User.ID.String(), nil, s.cfg.RefreshTokenTTL),
		TokenType:        token.TypeRefresh,
		UserID:           req.User.ID,
		SessionID:        req.SessionID,
		Scope:            token.JoinScopes(req.Scopes),
		AuthorizedTo:     req.ClientID,
	})
}

func (s *Service) GenerateIDToken(u *user.User, summary *access.UserAccessSummary, clientID, nonce string) (string, error) {
	return s.GenerateIDTokenFor(token.IDTokenRequest{User: u, Summary: summary, ClientID: clientID, Nonce: nonce})
}

func (s *Service) GenerateIDTokenFor(req token.IDTokenRequest) (string, error) {
	if req.User == nil {
		return "", errors.New("id token requires a user")
	}
	if req.ClientID == "" {
		return "", errors.New("id token requires a client ID audience")
	}
	includeProfile := len(req.Scopes) == 0 || token.HasScope(req.Scopes, token.ScopeProfile)
	includeEmail := len(req.Scopes) == 0 || token.HasScope(req.Scopes, token.ScopeEmail)

	claims := &token.IDTokenClaims{
		RegisteredClaims: s.registered(req.User.ID.String(), []string{req.ClientID}, s.cfg.IDTokenTTL),
		TokenType:        token.TypeID,
		UserID:           req.User.ID,
		Nonce:            req.Nonce,
		AuthorizedTo:     req.ClientID,
	}
	if includeEmail {
		claims.Email = req.User.Email
	}
	if includeProfile {
		claims.PreferredUsername = req.User.Username
	}
	if req.Summary != nil {
		claims.Roles = req.Summary.Roles
		claims.Permissions = req.Summary.Permissions
	}
	if req.AccessToken != "" {
		claims.AtHash = atHashRS256(req.AccessToken)
	}
	return s.sign(claims)
}

// GenerateClientAccessToken mints an access token for the client_credentials
// grant: no user, Subject = ClientID, no email or roles.
func (s *Service) GenerateClientAccessToken(req token.ClientAccessTokenRequest) (string, error) {
	if req.ClientID == "" {
		return "", errors.New("client access token requires a client ID")
	}
	claims := &token.AccessTokenClaims{
		RegisteredClaims: s.registered(req.ClientID, req.Audience, s.cfg.AccessTokenTTL),
		TokenType:        token.TypeAccess,
		Scope:            token.JoinScopes(req.Scopes),
		ClientID:         req.ClientID,
		AuthorizedTo:     req.ClientID,
	}
	return s.sign(claims)
}

// atHashRS256 is the OIDC Core §3.1.3.6 at_hash: left half of SHA-256(access_token)
// (because the signing algorithm is RS256), base64url-encoded without padding.
func atHashRS256(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// parse verifies signature (RS256 only, matching kid), issuer and expiry into claims.
func (s *Service) parse(tokenStr string, claims gojwt.Claims) error {
	_, err := gojwt.ParseWithClaims(tokenStr, claims,
		func(t *gojwt.Token) (interface{}, error) {
			if kid, _ := t.Header["kid"].(string); kid != s.keys.GetKID() {
				return nil, errors.New("unknown kid")
			}
			return s.keys.GetPublicKey(), nil
		},
		gojwt.WithValidMethods([]string{gojwt.SigningMethodRS256.Alg()}),
		gojwt.WithIssuer(s.cfg.Issuer),
		gojwt.WithExpirationRequired(),
		gojwt.WithIssuedAt(),
		gojwt.WithTimeFunc(s.now),
	)
	if errors.Is(err, gojwt.ErrTokenExpired) {
		return token.ErrTokenExpired
	}
	if err != nil {
		return token.ErrInvalidToken
	}
	return nil
}

func (s *Service) ValidateToken(tokenStr string) (*token.AccessTokenClaims, error) {
	claims := &token.AccessTokenClaims{}
	if err := s.parse(tokenStr, claims); err != nil {
		return nil, err
	}
	if claims.TokenType != token.TypeAccess {
		return nil, token.ErrInvalidTokenType
	}
	return claims, nil
}

func (s *Service) ValidateRefreshToken(tokenStr string) (*token.RefreshTokenClaims, error) {
	claims := &token.RefreshTokenClaims{}
	if err := s.parse(tokenStr, claims); err != nil {
		return nil, err
	}
	if claims.TokenType != token.TypeRefresh {
		return nil, token.ErrInvalidTokenType
	}
	return claims, nil
}

func (s *Service) GetJWKS(_ context.Context) (map[string]interface{}, error) {
	pub := s.keys.GetPublicKey().(*rsa.PublicKey)
	return map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "RSA",
			"use": "sig",
			"alg": gojwt.SigningMethodRS256.Alg(),
			"kid": s.keys.GetKID(),
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}, nil
}

package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/wailsb/opengo-idp/internal/domain/access"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// testKeys is generated once: RSA key generation dominates test time otherwise.
var testKeys = func() *RSAKeyProvider {
	k, err := GenerateRSAKeyProvider(2048)
	if err != nil {
		panic(err)
	}
	return k
}()

var testCfg = Config{
	Issuer:          "https://idp.test",
	AccessTokenTTL:  15 * time.Minute,
	RefreshTokenTTL: 24 * time.Hour,
	IDTokenTTL:      time.Hour,
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := NewService(testKeys, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testUser() *user.User {
	return &user.User{ID: uuid.New(), Email: "a@example.com", Username: "alice", IsActive: true}
}

func TestAccessToken_RoundTrip(t *testing.T) {
	s := newTestService(t)
	u := testUser()
	summary := &access.UserAccessSummary{Roles: []string{"admin"}, Permissions: []string{"user:read"}}

	tok, err := s.GenerateAccessToken(u, summary)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.ValidateToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.UserID != u.ID || claims.Subject != u.ID.String() || claims.Email != u.Email {
		t.Errorf("identity claims mismatch: %+v", claims)
	}
	if claims.Issuer != testCfg.Issuer || claims.TokenType != token.TypeAccess {
		t.Errorf("issuer/type mismatch: %+v", claims)
	}
	if !slices.Equal(claims.Roles, summary.Roles) || !slices.Equal(claims.Permissions, summary.Permissions) {
		t.Errorf("access claims mismatch: %+v", claims)
	}
}

func TestRefreshToken_RoundTrip(t *testing.T) {
	s := newTestService(t)
	u := testUser()

	tok, err := s.GenerateRefreshToken(u, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.ValidateRefreshToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.SessionID != "sess-1" || claims.UserID != u.ID {
		t.Errorf("claims mismatch: %+v", claims)
	}

	if _, err := s.GenerateRefreshToken(u, ""); err == nil {
		t.Error("expected error for empty session ID")
	}
}

func TestIDToken_Claims(t *testing.T) {
	s := newTestService(t)
	u := testUser()

	tok, err := s.GenerateIDToken(u, nil, "client-1", "n0nce")
	if err != nil {
		t.Fatal(err)
	}
	claims := &token.IDTokenClaims{}
	if err := s.parse(tok, claims); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(claims.Audience, gojwt.ClaimStrings{"client-1"}) {
		t.Errorf("audience = %v", claims.Audience)
	}
	if claims.Nonce != "n0nce" || claims.PreferredUsername != "alice" || claims.TokenType != token.TypeID {
		t.Errorf("claims mismatch: %+v", claims)
	}

	if _, err := s.GenerateIDToken(u, nil, "", ""); err == nil {
		t.Error("expected error for empty client ID")
	}
}

func TestTokenTypeConfusion(t *testing.T) {
	s := newTestService(t)
	u := testUser()

	refresh, _ := s.GenerateRefreshToken(u, "sess-1")
	if _, err := s.ValidateToken(refresh); !errors.Is(err, token.ErrInvalidTokenType) {
		t.Errorf("refresh as access: got %v, want ErrInvalidTokenType", err)
	}
	accessTok, _ := s.GenerateAccessToken(u, nil)
	if _, err := s.ValidateRefreshToken(accessTok); !errors.Is(err, token.ErrInvalidTokenType) {
		t.Errorf("access as refresh: got %v, want ErrInvalidTokenType", err)
	}
	idTok, _ := s.GenerateIDToken(u, nil, "c", "")
	if _, err := s.ValidateToken(idTok); !errors.Is(err, token.ErrInvalidTokenType) {
		t.Errorf("id as access: got %v, want ErrInvalidTokenType", err)
	}
}

func TestValidate_Expired(t *testing.T) {
	s := newTestService(t)
	tok, _ := s.GenerateAccessToken(testUser(), nil)

	s.now = func() time.Time { return time.Now().Add(testCfg.AccessTokenTTL + time.Minute) }
	if _, err := s.ValidateToken(tok); !errors.Is(err, token.ErrTokenExpired) {
		t.Fatalf("got %v, want ErrTokenExpired", err)
	}
}

func TestValidate_Rejects(t *testing.T) {
	s := newTestService(t)
	u := testUser()
	valid, _ := s.GenerateAccessToken(u, nil)

	otherKeys, err := GenerateRSAKeyProvider(2048)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, _ := NewService(otherKeys, testCfg)
	foreign, _ := otherSigner.GenerateAccessToken(u, nil)

	otherIssuerCfg := testCfg
	otherIssuerCfg.Issuer = "https://evil.test"
	otherIssuer, _ := NewService(testKeys, otherIssuerCfg)
	wrongIss, _ := otherIssuer.GenerateAccessToken(u, nil)

	// alg=none must never be accepted.
	none := gojwt.NewWithClaims(gojwt.SigningMethodNone, &token.AccessTokenClaims{
		RegisteredClaims: s.registered(u.ID.String(), nil, time.Hour),
		TokenType:        token.TypeAccess,
	})
	none.Header["kid"] = testKeys.GetKID()
	noneTok, _ := none.SignedString(gojwt.UnsafeAllowNoneSignatureType)

	cases := map[string]string{
		"garbage":      "not.a.jwt",
		"tampered":     valid[:len(valid)-4] + "AAAA",
		"foreign key":  foreign,
		"wrong issuer": wrongIss,
		"alg none":     noneTok,
		"empty":        "",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.ValidateToken(tok); !errors.Is(err, token.ErrInvalidToken) {
				t.Errorf("got %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestGetJWKS(t *testing.T) {
	s := newTestService(t)
	jwks, err := s.GetJWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keys := jwks["keys"].([]map[string]interface{})
	if len(keys) != 1 {
		t.Fatalf("got %d keys", len(keys))
	}
	k := keys[0]
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" || k["kid"] != testKeys.GetKID() {
		t.Errorf("unexpected key metadata: %v", k)
	}

	// The published modulus/exponent must reconstruct the signing public key.
	n, _ := base64.RawURLEncoding.DecodeString(k["n"].(string))
	e, _ := base64.RawURLEncoding.DecodeString(k["e"].(string))
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if !pub.Equal(testKeys.GetPublicKey()) {
		t.Error("JWKS key does not match the signing key")
	}
}

func TestNewService_Validation(t *testing.T) {
	bad := testCfg
	bad.Issuer = ""
	if _, err := NewService(testKeys, bad); err == nil {
		t.Error("expected error for empty issuer")
	}
	bad = testCfg
	bad.AccessTokenTTL = 0
	if _, err := NewService(testKeys, bad); err == nil {
		t.Error("expected error for zero TTL")
	}
}

func TestKeyProvider_PEMAndKID(t *testing.T) {
	key := testKeys.GetPrivateKey().(*rsa.PrivateKey)
	dir := t.TempDir()

	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	der8, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})

	for name, data := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".pem")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			p, err := LoadRSAKeyProvider(path)
			if err != nil {
				t.Fatal(err)
			}
			// KID is deterministic for the same key.
			if p.GetKID() != testKeys.GetKID() {
				t.Errorf("kid = %q, want %q", p.GetKID(), testKeys.GetKID())
			}
		})
	}

	if _, err := ParseRSAPrivateKeyPEM([]byte("garbage")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := LoadRSAKeyProvider(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNewRSAKeyProvider_RejectsWeakKey(t *testing.T) {
	if _, err := GenerateRSAKeyProvider(1024); err == nil {
		t.Fatal("expected error for 1024-bit key")
	}
	if _, err := NewRSAKeyProvider(nil); err == nil {
		t.Fatal("expected error for nil key")
	}
}

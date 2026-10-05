// Package jwt implements token.Service with RS256-signed JWTs.
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const minRSABits = 2048

// RSAKeyProvider holds a single RSA signing key. The KID is derived from the public
// key, so the same key always gets the same KID across restarts.
type RSAKeyProvider struct {
	private *rsa.PrivateKey
	kid     string
}

func NewRSAKeyProvider(key *rsa.PrivateKey) (*RSAKeyProvider, error) {
	if key == nil {
		return nil, errors.New("rsa key is nil")
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("rsa key must be at least %d bits", minRSABits)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return &RSAKeyProvider{
		private: key,
		kid:     base64.RawURLEncoding.EncodeToString(sum[:16]),
	}, nil
}

// GenerateRSAKeyProvider creates a fresh key. Tokens signed with it become invalid on
// restart, so it is meant for development and tests only.
func GenerateRSAKeyProvider(bits int) (*RSAKeyProvider, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	return NewRSAKeyProvider(key)
}

// ParseRSAPrivateKeyPEM accepts PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") blocks.
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not an RSA key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

func LoadRSAKeyProvider(path string) (*RSAKeyProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	key, err := ParseRSAPrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return NewRSAKeyProvider(key)
}

func (p *RSAKeyProvider) GetPrivateKey() interface{} { return p.private }
func (p *RSAKeyProvider) GetPublicKey() interface{}  { return &p.private.PublicKey }
func (p *RSAKeyProvider) GetKID() string             { return p.kid }

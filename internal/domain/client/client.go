package client

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrClientNotFound       = errors.New("client not found")
	ErrClientAlreadyExists  = errors.New("client already exists")
	ErrInvalidClientName    = errors.New("client name must not be empty")
	ErrInvalidRedirectURI   = errors.New("redirect URI must be absolute and have no fragment")
	ErrMissingRedirectURI   = errors.New("authorization_code grant requires at least one redirect URI")
	ErrUnsupportedGrantType = errors.New("unsupported grant type")
	ErrPublicClientGrant    = errors.New("client_credentials grant requires a confidential client")
)

// OAuth2 grant types supported by the IDP.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
)

var supportedGrantTypes = []string{
	GrantTypeAuthorizationCode,
	GrantTypeRefreshToken,
	GrantTypeClientCredentials,
}

const (
	clientIDBytes     = 16
	clientSecretBytes = 32
)

// Client is an OAuth2/OIDC relying party registered with the IDP.
type Client struct {
	ID                uuid.UUID
	ClientID          string
	ClientSecretHash  string
	Name              string
	RedirectURIs      []string
	AllowedGrantTypes []string
	IsConfidential    bool
	CreatedAt         time.Time
}

// NewClient registers a client. For confidential clients it returns the generated plain
// secret, which is only stored hashed and must be shown to the caller exactly once.
// Public clients get an empty secret.
func NewClient(name string, redirectURIs, grantTypes []string, isConfidential bool) (*Client, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", ErrInvalidClientName
	}

	for _, gt := range grantTypes {
		if !slices.Contains(supportedGrantTypes, gt) {
			return nil, "", ErrUnsupportedGrantType
		}
		if gt == GrantTypeClientCredentials && !isConfidential {
			return nil, "", ErrPublicClientGrant
		}
	}

	if slices.Contains(grantTypes, GrantTypeAuthorizationCode) && len(redirectURIs) == 0 {
		return nil, "", ErrMissingRedirectURI
	}
	for _, uri := range redirectURIs {
		if !isValidRedirectURI(uri) {
			return nil, "", ErrInvalidRedirectURI
		}
	}

	var plainSecret, secretHash string
	if isConfidential {
		plainSecret = randomToken(clientSecretBytes)
		hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", err
		}
		secretHash = string(hash)
	}

	return &Client{
		ID:                uuid.New(),
		ClientID:          randomToken(clientIDBytes),
		ClientSecretHash:  secretHash,
		Name:              name,
		RedirectURIs:      slices.Clone(redirectURIs),
		AllowedGrantTypes: slices.Clone(grantTypes),
		IsConfidential:    isConfidential,
		CreatedAt:         time.Now().UTC(),
	}, plainSecret, nil
}

// VerifySecret checks plainSecret against the stored hash. Public clients have no
// secret and always fail.
func (c *Client) VerifySecret(plainSecret string) bool {
	if !c.IsConfidential || c.ClientSecretHash == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(c.ClientSecretHash), []byte(plainSecret))
	return err == nil
}

// IsRedirectURIAllowed uses exact string matching, as required by OAuth 2.1 and the
// OAuth 2.0 Security BCP; prefix or wildcard matching enables open redirects.
func (c *Client) IsRedirectURIAllowed(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

func (c *Client) IsGrantTypeAllowed(grantType string) bool {
	return slices.Contains(c.AllowedGrantTypes, grantType)
}

// isValidRedirectURI enforces RFC 6749 §3.1.2: absolute URI without a fragment.
func isValidRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	// Check the raw string: url.Parse drops an empty fragment ("https://x/#").
	return u.IsAbs() && !strings.Contains(uri, "#")
}

// randomToken returns a URL-safe random string. crypto/rand.Read never returns an
// error on supported platforms; it crashes the program if the OS source fails.
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

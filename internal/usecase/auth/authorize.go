package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/wailsb/opengo-idp/internal/domain/authcode"
	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/session"
	"github.com/wailsb/opengo-idp/internal/domain/token"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

// IssueAuthCodeInput carries the authenticated parts of an /authorize request:
// the caller has already validated the client, redirect_uri and scope.
type IssueAuthCodeInput struct {
	Client              *client.Client
	UserID              uuid.UUID
	SessionID           string
	RedirectURI         string
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// IssueAuthCode persists a fresh authorization code and returns it. The handler
// is responsible for redirecting the user agent with the code in the URL.
func (s *Service) IssueAuthCode(ctx context.Context, in IssueAuthCodeInput) (*authcode.AuthCode, error) {
	if s.authCodeRepo == nil {
		return nil, errors.New("auth: authorization code repository not configured")
	}
	if in.Client == nil {
		return nil, ErrInvalidClient
	}
	if !in.Client.IsGrantTypeAllowed(client.GrantTypeAuthorizationCode) {
		return nil, ErrUnauthorizedClient
	}
	if !in.Client.IsRedirectURIAllowed(in.RedirectURI) {
		return nil, ErrInvalidGrant
	}

	code, err := authcode.New(
		in.Client.ClientID,
		in.RedirectURI,
		token.JoinScopes(in.Scopes),
		in.Nonce,
		in.CodeChallenge,
		in.CodeChallengeMethod,
		in.UserID,
		in.SessionID,
		s.authCodeTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("new auth code: %w", err)
	}
	if err := s.authCodeRepo.Create(ctx, code); err != nil {
		return nil, fmt.Errorf("store auth code: %w", err)
	}
	return code, nil
}

// AuthCodeGrantInput feeds the authorization_code grant on /token. The caller
// has already authenticated the client (basic/post).
type AuthCodeGrantInput struct {
	Client       *client.Client
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// AuthorizationCode exchanges a single-use code for tokens, enforcing all of:
// client match, redirect_uri match, PKCE verifier match. Reuse detection: because
// the repository uses GETDEL, a reused code looks like ErrAuthCodeNotFound. In
// that case we eagerly revoke the session that originally received the code so
// any tokens previously issued become unusable.
func (s *Service) AuthorizationCode(ctx context.Context, in AuthCodeGrantInput) (*TokenPair, error) {
	if s.authCodeRepo == nil {
		return nil, errors.New("auth: authorization code repository not configured")
	}
	if in.Client == nil {
		return nil, ErrInvalidClient
	}
	if !in.Client.IsGrantTypeAllowed(client.GrantTypeAuthorizationCode) {
		return nil, ErrUnauthorizedClient
	}
	if in.Code == "" {
		return nil, ErrInvalidGrant
	}

	code, err := s.authCodeRepo.GetAndDelete(ctx, in.Code)
	if errors.Is(err, authcode.ErrAuthCodeNotFound) || errors.Is(err, authcode.ErrAuthCodeExpired) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("consume auth code: %w", err)
	}

	// Bind to the authenticated client (prevent cross-client code use).
	if code.ClientID != in.Client.ClientID {
		// Treat as reuse / theft: revoke the session the code was tied to.
		if code.SessionID != "" {
			_ = s.sessionRepo.Delete(ctx, code.SessionID)
		}
		return nil, ErrInvalidGrant
	}

	// RFC 6749 §4.1.3: redirect_uri must match the original request exactly.
	if code.RedirectURI != in.RedirectURI {
		return nil, ErrInvalidGrant
	}

	if err := verifyPKCE(code, in.CodeVerifier, in.Client.IsConfidential); err != nil {
		return nil, err
	}

	// Load the user and session; both must still be valid.
	u, err := s.userRepo.GetByID(ctx, code.UserID)
	if errors.Is(err, user.ErrUserNotFound) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if u.IsDeleted || !u.IsActive {
		return nil, ErrInvalidGrant
	}

	if code.SessionID != "" {
		sess, err := s.sessionRepo.GetByID(ctx, code.SessionID)
		if errors.Is(err, session.ErrSessionNotFound) {
			return nil, ErrInvalidGrant
		}
		if err != nil {
			return nil, fmt.Errorf("get session: %w", err)
		}
		if err := sess.IsValid(); err != nil {
			return nil, ErrInvalidGrant
		}
		if sess.UserID != u.ID {
			return nil, ErrInvalidGrant
		}
	}

	scopes := token.ParseScopes(code.Scope)
	return s.issueTokensScoped(ctx, u, code.SessionID, in.Client.ClientID, code.Nonce, scopes, true)
}

// verifyPKCE checks the code_verifier against the stored challenge. PKCE is
// mandatory for public clients (RFC 7636); confidential clients may skip it but
// if they included a challenge at /authorize they must supply the verifier.
func verifyPKCE(code *authcode.AuthCode, verifier string, confidential bool) error {
	if code.CodeChallenge == "" {
		if !confidential {
			// Public client without PKCE should never have been issued a code.
			return ErrInvalidGrant
		}
		return nil
	}
	if verifier == "" {
		return ErrInvalidGrant
	}
	switch code.CodeChallengeMethod {
	case authcode.ChallengeMethodS256, "":
		sum := sha256.Sum256([]byte(verifier))
		got := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(code.CodeChallenge)) != 1 {
			return ErrInvalidGrant
		}
		return nil
	case authcode.ChallengeMethodPlain:
		if subtle.ConstantTimeCompare([]byte(verifier), []byte(code.CodeChallenge)) != 1 {
			return ErrInvalidGrant
		}
		return nil
	default:
		return ErrInvalidGrant
	}
}

// ComputeS256Challenge is exposed for tests and for the (future) consent flow,
// so callers compute PKCE challenges the same way the verifier does.
func ComputeS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

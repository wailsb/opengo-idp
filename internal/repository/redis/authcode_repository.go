package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/wailsb/opengo-idp/internal/domain/authcode"
)

// Storage layout:
//
//	idp:authcode:<sha256(code)>  STRING (JSON), PEXPIREAT = ExpiresAt
//
// The raw code is a bearer credential and never stored verbatim; only its
// SHA-256 digest keys the entry. GetAndDelete uses GETDEL so a leaked code can
// be exchanged at most once even under concurrent attempts.

const authCodeKeyPrefix = "idp:authcode:"

type AuthCodeRepository struct {
	client redis.UniversalClient
}

var _ authcode.Repository = (*AuthCodeRepository)(nil)

func NewAuthCodeRepository(client redis.UniversalClient) *AuthCodeRepository {
	return &AuthCodeRepository{client: client}
}

func authCodeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return authCodeKeyPrefix + hex.EncodeToString(sum[:])
}

// storedAuthCode is the on-wire shape. Field renames orphan existing entries.
type storedAuthCode struct {
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	SessionID           string    `json:"session_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	Nonce               string    `json:"nonce"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func (r *AuthCodeRepository) Create(ctx context.Context, a *authcode.AuthCode) error {
	now := time.Now().UTC()
	if !now.Before(a.ExpiresAt) {
		return authcode.ErrAuthCodeExpired
	}
	payload, err := json.Marshal(storedAuthCode{
		ClientID:            a.ClientID,
		UserID:              a.UserID.String(),
		SessionID:           a.SessionID,
		RedirectURI:         a.RedirectURI,
		Scope:               a.Scope,
		Nonce:               a.Nonce,
		CodeChallenge:       a.CodeChallenge,
		CodeChallengeMethod: a.CodeChallengeMethod,
		CreatedAt:           a.CreatedAt,
		ExpiresAt:           a.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("redis create authcode: marshal: %w", err)
	}

	// SET NX guarantees we never clobber a colliding code (astronomically unlikely
	// at 256 bits of entropy, but the branch costs nothing).
	ok, err := r.client.SetNX(ctx, authCodeKey(a.Code), payload, time.Until(a.ExpiresAt)).Result()
	if err != nil {
		return fmt.Errorf("redis create authcode: %w", err)
	}
	if !ok {
		return errors.New("redis create authcode: code already exists")
	}
	return nil
}

// GetAndDelete uses GETDEL (Redis ≥6.2) to atomically fetch and remove the entry,
// ensuring single-use semantics.
func (r *AuthCodeRepository) GetAndDelete(ctx context.Context, code string) (*authcode.AuthCode, error) {
	if code == "" {
		return nil, authcode.ErrAuthCodeNotFound
	}

	raw, err := r.client.GetDel(ctx, authCodeKey(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, authcode.ErrAuthCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis getdel authcode: %w", err)
	}

	var s storedAuthCode
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("redis getdel authcode: unmarshal: %w", err)
	}
	userID, err := uuid.Parse(s.UserID)
	if err != nil {
		return nil, fmt.Errorf("redis getdel authcode: user_id: %w", err)
	}

	ac := &authcode.AuthCode{
		Code:                code,
		ClientID:            s.ClientID,
		UserID:              userID,
		SessionID:           s.SessionID,
		RedirectURI:         s.RedirectURI,
		Scope:               s.Scope,
		Nonce:               s.Nonce,
		CodeChallenge:       s.CodeChallenge,
		CodeChallengeMethod: s.CodeChallengeMethod,
		CreatedAt:           s.CreatedAt.UTC(),
		ExpiresAt:           s.ExpiresAt.UTC(),
	}
	if ac.IsExpired() {
		return nil, authcode.ErrAuthCodeExpired
	}
	return ac, nil
}

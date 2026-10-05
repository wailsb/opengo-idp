package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/wailsb/opengo-idp/internal/domain/session"
)

// Storage layout:
//
//	idp:session:<sha256(id)>  HASH  session fields, PEXPIREAT = ExpiresAt
//	idp:user:<uuid>:sessions  ZSET  member sha256(id), score ExpiresAt (unix ms);
//	                                the key expires with its latest session
//
// The raw session ID is a bearer credential and is never written to Redis; only its
// SHA-256 digest is. Writes that touch both keys run as Lua scripts so concurrent
// logins, refreshes, revocations and "log out everywhere" cannot interleave.
//
// DeleteAllByUserID derives session keys inside its script, so this repository
// supports standalone and Sentinel deployments, not Redis Cluster.
const (
	sessionKeyPrefix = "idp:session:"
	maxSessionIDLen  = 256
)

// Hash field names. These are the persisted format: renaming one orphans stored data.
const (
	fieldUserID    = "user_id"
	fieldUserAgent = "user_agent"
	fieldIPAddress = "ip_address"
	fieldIsRevoked = "is_revoked"
	fieldCreatedAt = "created_at"
	fieldExpiresAt = "expires_at"
)

// Script results shared by createScript and updateScript.
const (
	scriptOK           = 1
	scriptConflict     = 0
	scriptRevoked      = -1
	scriptUserMismatch = -2
)

var errUserMismatch = errors.New("session belongs to a different user")

// createScript inserts the session only if its key is free, prunes expired entries
// from the user index, indexes the new session and stretches the index TTL to its
// latest session.
//
// KEYS: session, user index. ARGV: member, expiresAtMs, nowMs, field/value pairs...
var createScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
	return 0
end
for i = 4, #ARGV, 2 do
	redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
end
redis.call('PEXPIREAT', KEYS[1], ARGV[2])

redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
local last = redis.call('ZRANGE', KEYS[2], -1, -1, 'WITHSCORES')
redis.call('PEXPIREAT', KEYS[2], last[2])
return 1
`)

// updateScript overwrites mutable fields of an existing session. It never recreates
// a deleted session and never un-revokes one; re-saving an already revoked session as
// revoked is an idempotent no-op.
//
// KEYS: session, user index. ARGV: member, expiresAtMs, nowMs, userID, isRevoked, field/value pairs...
var updateScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
	return 0
end
if redis.call('HGET', KEYS[1], 'user_id') ~= ARGV[4] then
	return -2
end
if redis.call('HGET', KEYS[1], 'is_revoked') == '1' then
	if ARGV[5] == '1' then
		return 1
	end
	return -1
end
for i = 6, #ARGV, 2 do
	redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
end
redis.call('PEXPIREAT', KEYS[1], ARGV[2])

redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
local last = redis.call('ZRANGE', KEYS[2], -1, -1, 'WITHSCORES')
redis.call('PEXPIREAT', KEYS[2], last[2])
return 1
`)

// deleteAllScript deletes every indexed session and the index in one atomic step, so
// a concurrent Create either lands before (and is deleted) or after (and survives
// as a new login).
//
// KEYS: user index. ARGV: session key prefix.
var deleteAllScript = redis.NewScript(`
local members = redis.call('ZRANGE', KEYS[1], 0, -1)
for _, member in ipairs(members) do
	redis.call('DEL', ARGV[1] .. member)
end
redis.call('DEL', KEYS[1])
return #members
`)

type SessionRepository struct {
	client redis.UniversalClient
}

var _ session.Repository = (*SessionRepository)(nil)

// NewSessionRepository accepts a standalone or Sentinel-backed client. Redis Cluster is
// not supported; see the storage layout notes above.
func NewSessionRepository(client redis.UniversalClient) *SessionRepository {
	return &SessionRepository{client: client}
}

// sessionMember is the digest that identifies a session in Redis.
func sessionMember(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func sessionKey(member string) string {
	return sessionKeyPrefix + member
}

func userSessionsKey(userID uuid.UUID) string {
	return "idp:user:" + userID.String() + ":sessions"
}

// isPlausibleID rejects IDs that cannot have been issued, without a Redis round trip.
func isPlausibleID(id string) bool {
	return id != "" && len(id) <= maxSessionIDLen
}

func (r *SessionRepository) Create(ctx context.Context, s *session.Session) error {
	now := time.Now().UTC()
	if !now.Before(s.ExpiresAt) {
		return session.ErrSessionExpired
	}

	member := sessionMember(s.ID)
	args := append([]any{member, s.ExpiresAt.UnixMilli(), now.UnixMilli()}, sessionFields(s)...)

	res, err := createScript.Run(ctx, r.client, []string{sessionKey(member), userSessionsKey(s.UserID)}, args...).Int()
	if err != nil {
		return fmt.Errorf("redis create session: %w", err)
	}
	if res == scriptConflict {
		return errors.New("redis create session: session ID already exists")
	}
	return nil
}

func (r *SessionRepository) GetByID(ctx context.Context, id string) (*session.Session, error) {
	if !isPlausibleID(id) {
		return nil, session.ErrSessionNotFound
	}

	fields, err := r.client.HGetAll(ctx, sessionKey(sessionMember(id))).Result()
	if err != nil {
		return nil, fmt.Errorf("redis get session: %w", err)
	}
	if len(fields) == 0 {
		return nil, session.ErrSessionNotFound
	}

	s, err := parseSession(id, fields)
	if err != nil {
		return nil, fmt.Errorf("redis get session: %w", err)
	}
	return s, nil
}

// Update persists IsRevoked, ExpiresAt, UserAgent and IPAddress. It returns
// ErrSessionNotFound if the session was deleted or expired meanwhile, and
// ErrSessionRevoked if it was revoked meanwhile and s is not. A session whose
// ExpiresAt has passed is deleted.
func (r *SessionRepository) Update(ctx context.Context, s *session.Session) error {
	now := time.Now().UTC()
	if !now.Before(s.ExpiresAt) {
		return r.Delete(ctx, s.ID)
	}

	member := sessionMember(s.ID)
	args := []any{
		member, s.ExpiresAt.UnixMilli(), now.UnixMilli(), s.UserID.String(), formatBool(s.IsRevoked),
		fieldUserAgent, s.UserAgent,
		fieldIPAddress, s.IPAddress,
		fieldIsRevoked, formatBool(s.IsRevoked),
		fieldExpiresAt, formatTime(s.ExpiresAt),
	}

	res, err := updateScript.Run(ctx, r.client, []string{sessionKey(member), userSessionsKey(s.UserID)}, args...).Int()
	if err != nil {
		return fmt.Errorf("redis update session: %w", err)
	}
	switch res {
	case scriptOK:
		return nil
	case scriptConflict:
		return session.ErrSessionNotFound
	case scriptRevoked:
		return session.ErrSessionRevoked
	case scriptUserMismatch:
		return fmt.Errorf("redis update session: %w", errUserMismatch)
	default:
		return fmt.Errorf("redis update session: unexpected script result %d", res)
	}
}

// Delete removes the session. It is idempotent and does not decode the stored
// session, so a corrupt entry can still be deleted.
func (r *SessionRepository) Delete(ctx context.Context, id string) error {
	if !isPlausibleID(id) {
		return nil
	}

	member := sessionMember(id)
	key := sessionKey(member)

	var userIDCmd *redis.StringCmd
	_, err := r.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		userIDCmd = pipe.HGet(ctx, key, fieldUserID)
		pipe.Del(ctx, key)
		return nil
	})
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis delete session: %w", err)
	}

	// The session key is already gone. Failing to unindex it only leaves a stale
	// member, which is pruned once its score passes and is harmless to DeleteAllByUserID.
	userID, err := uuid.Parse(userIDCmd.Val())
	if err != nil {
		return nil
	}
	if err := r.client.ZRem(ctx, userSessionsKey(userID), member).Err(); err != nil {
		return fmt.Errorf("redis unindex session: %w", err)
	}
	return nil
}

func (r *SessionRepository) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	err := deleteAllScript.Run(ctx, r.client, []string{userSessionsKey(userID)}, sessionKeyPrefix).Err()
	if err != nil {
		return fmt.Errorf("redis delete all user sessions: %w", err)
	}
	return nil
}

func sessionFields(s *session.Session) []any {
	return []any{
		fieldUserID, s.UserID.String(),
		fieldUserAgent, s.UserAgent,
		fieldIPAddress, s.IPAddress,
		fieldIsRevoked, formatBool(s.IsRevoked),
		fieldCreatedAt, formatTime(s.CreatedAt),
		fieldExpiresAt, formatTime(s.ExpiresAt),
	}
}

func parseSession(id string, fields map[string]string) (*session.Session, error) {
	userID, err := uuid.Parse(fields[fieldUserID])
	if err != nil {
		return nil, fmt.Errorf("corrupt session field %s: %w", fieldUserID, err)
	}
	isRevoked, err := strconv.ParseBool(fields[fieldIsRevoked])
	if err != nil {
		return nil, fmt.Errorf("corrupt session field %s: %w", fieldIsRevoked, err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, fields[fieldCreatedAt])
	if err != nil {
		return nil, fmt.Errorf("corrupt session field %s: %w", fieldCreatedAt, err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, fields[fieldExpiresAt])
	if err != nil {
		return nil, fmt.Errorf("corrupt session field %s: %w", fieldExpiresAt, err)
	}

	return &session.Session{
		ID:        id,
		UserID:    userID,
		UserAgent: fields[fieldUserAgent],
		IPAddress: fields[fieldIPAddress],
		IsRevoked: isRevoked,
		CreatedAt: createdAt.UTC(),
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

// formatBool matches the '1' the Lua scripts compare against.
func formatBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

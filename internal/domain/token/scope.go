package token

import "strings"

// Standard OIDC scopes handled by the IDP.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

// SupportedScopes advertises the scopes the IDP will honour; anything not in
// this list is silently dropped by ParseScopes.
var SupportedScopes = []string{
	ScopeOpenID,
	ScopeProfile,
	ScopeEmail,
	ScopeOfflineAccess,
}

// ParseScopes splits a space-separated scope string (RFC 6749 §3.3) and keeps only
// supported, non-empty, non-duplicate values, preserving the request order.
func ParseScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, s := range strings.Fields(raw) {
		if _, dup := seen[s]; dup {
			continue
		}
		for _, allowed := range SupportedScopes {
			if s == allowed {
				seen[s] = struct{}{}
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// HasScope reports whether scope is present in scopes.
func HasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// JoinScopes serialises scopes as RFC 6749 §3.3 expects.
func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

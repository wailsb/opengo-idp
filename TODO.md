# TODO: road to a complete OIDC identity provider

Phases are ordered by dependency: finish each one before starting the next. Within a phase, the items go roughly from top to bottom. Every item should ship with unit tests, following the existing fakes-based style.

## ✅ Done

- [x] Domain: user, client, session, access (RBAC plus direct permissions), token claims and ports
- [x] Postgres repositories, migration and integration tests
- [x] Redis session repository
- [x] Config loader from environment variables, with validation
- [x] bcrypt password hasher (configurable cost, rejects passwords over 72 bytes)
- [x] RS256 JWT service: access, refresh and ID tokens, validation, JWKS, PEM key loading, deterministic `kid`
- [x] Auth usecase: login (email or username), refresh, logout, logout from all devices, session validation, timing-safe handling of unknown users
- [x] Admin usecase: create user (with validation), create client
- [x] HTTP API: `/login`, `/logout`, `/token` (refresh), `/userinfo`, discovery, JWKS, health
- [x] `cmd/idp` with `serve`, `create-user`, `create-client`; graceful shutdown
- [x] Dockerfile, docker-compose, `.env.example`

---

## Phase 1: Real OAuth2 Authorization Code flow (highest priority)

This phase is what lets standard OIDC client libraries (e.g. `coreos/go-oidc`, `next-auth`, `oidc-client-ts`) connect.

1. [ ] **Authorization code domain and storage**
   - `domain/authcode`: code, client ID, user ID, session ID, redirect URI, scope, nonce, PKCE challenge and method, expiry (≤60s)
   - Redis repository with **single-use** semantics: atomic `GETDEL`
2. [ ] **`GET /authorize` endpoint**
   - Validate `response_type=code`, `client_id`, exact `redirect_uri`, `scope` (must contain `openid` for OIDC), `state`, `nonce`
   - **Require PKCE (`S256`) for public clients**; recommended for all clients
   - No valid session cookie → redirect to the login page, then return to `/authorize`
   - Errors before `redirect_uri` is validated → show an error page, **never redirect**
3. [ ] **Login page (HTML)**
   - Server-rendered form posting to `/login`, with a CSRF token
   - Keep the JSON `/login` for first-party apps, or move it to `/api/login`
4. [ ] **`authorization_code` grant on `/token`**
   - Verify the code, its client, its `redirect_uri` and the PKCE `code_verifier`
   - Detect code reuse → revoke the tokens issued from that code
5. [ ] **Client authentication on `/token`** (RFC 6749 §2.3)
   - `client_secret_basic` and `client_secret_post` for confidential clients
   - Public clients: `client_id` only, and PKCE is mandatory
   - Enforce `client.IsGrantTypeAllowed` for every grant
   - Bind refresh tokens to the client they were issued to (`azp` claim)
6. [ ] **`client_credentials` grant** for machine-to-machine access tokens (no user, no refresh token)
7. [ ] **Scopes and claims**
   - Support `openid`, `profile`, `email` and `offline_access` (refresh token only when requested)
   - Filter `/userinfo` and ID token claims by scope
   - Add `aud` to access tokens (the resource server or client) and `azp` / `at_hash` to ID tokens
8. [ ] **Complete the discovery document**: `authorization_endpoint`, `response_types_supported`, `scopes_supported`, `code_challenge_methods_supported`, updated auth methods
9. [ ] **Consent screen**, plus storage of granted scopes per user and client (first-party clients can skip it)

## Phase 2: Token lifecycle and security

1. [ ] **Refresh token rotation with reuse detection.** Store the current refresh `jti` on the session; a reused old `jti` revokes the whole session (OAuth 2.0 Security BCP §4.14)
2. [ ] **Token revocation** `POST /revoke` (RFC 7009)
3. [ ] **Token introspection** `POST /introspect` (RFC 7662), for confidential clients only
4. [ ] **RP-initiated logout** `GET /logout?id_token_hint=…&post_logout_redirect_uri=…` (OIDC RP-Initiated Logout 1.0)
5. [ ] **Rate limiting** on `/login` and `/token`, per IP and per account (Redis sliding window), plus temporary lockout after N failures
6. [ ] **Key rotation**: support several keys in `KeyProvider` (one active signer, older keys kept in the JWKS until their tokens expire)
7. [ ] **Trusted proxy config** so the real client IP is read from `X-Forwarded-For` only behind known proxies
8. [ ] **Security headers**: `Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy`, HSTS
9. [ ] **Audit log** for login success and failure, logout, token issuance and admin actions (structured, with no secrets)
10. [ ] Optional: ES256 / EdDSA signing support

## Phase 3: User self-service

1. [ ] Public registration, behind a config flag (it reuses `admin.CreateUser` validation)
2. [ ] Email verification (an `email_verified` column and claim, single-use tokens in Redis, a `Mailer` port with SMTP and log-only adapters)
3. [ ] Password reset ("forgot password") with single-use, short-lived tokens; it invalidates every session
4. [ ] Change password (requires the current one) and change email (requires re-verification)
5. [ ] Password policy: a breached-password check (k-anonymity HIBP) and configurable rules
6. [ ] List and revoke my sessions (needs a `ListByUserID` method on the session repository)
7. [ ] MFA: TOTP enrolment, verification at login, recovery codes; later WebAuthn/passkeys

## Phase 4: Admin API

1. [ ] Admin authentication: access tokens carrying `admin:*` permissions, and middleware that checks `UserAccessSummary.HasPermission`
2. [ ] Users: list (paginated), get, update, disable/enable, delete, assign roles and direct permissions
3. [ ] Clients: list, get, update redirect URIs and grants, rotate secret, delete
4. [ ] Roles and permissions CRUD (the repository already supports create/get/assign; add list, update, delete and unassign)
5. [ ] Bootstrap: seed an initial admin role and permissions on first start (or via `idp bootstrap`)
6. [ ] OpenAPI spec for the public and admin APIs

## Phase 5: Operations and quality

1. [ ] Migrations run by the binary (`idp migrate up|down`, e.g. `golang-migrate` with embedded files) instead of docker-entrypoint
2. [ ] Readiness probe `/readyz` that checks Postgres and Redis (`/healthz` stays a liveness check)
3. [ ] Prometheus metrics (request latency, login success and failure, tokens issued) and OpenTelemetry tracing
4. [ ] Request ID middleware, propagated into logs
5. [ ] Redis session repository tests (miniredis or testcontainers) and a CI job running the Postgres integration tests
6. [ ] HTTP end-to-end test: real JWT service plus real Postgres and Redis (testcontainers), through the full login → userinfo → refresh → logout flow
7. [ ] CI (GitHub Actions): `gofmt`, `go vet`, `staticcheck`, `govulncheck`, `go test -race -cover`, Docker build
8. [ ] Makefile / Taskfile for common commands
9. [ ] Run the OpenID Foundation conformance suite (Basic OP profile) once Phase 1 is complete

## Known cleanups

- [ ] `user.User.CheckPassword`, `user.NewUser` (fixed bcrypt cost) and `user.ErrInvalidCredentials` duplicate the hasher and the auth-layer errors. Remove them once nothing uses them, so all hashing goes through `PasswordHasher`
- [ ] `users.is_enabled` in SQL is `IsActive` in Go. Rename one of them for consistency
- [ ] Email uniqueness relies on emails being stored lowercased by `admin.CreateUser`. Consider a `UNIQUE (lower(email))` index or a `citext` column
- [ ] `/login` returns tokens in the body for first-party use. Once `/authorize` exists, decide whether it should only set the session cookie

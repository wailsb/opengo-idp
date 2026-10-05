# opengo-idp

An identity provider written in Go. It is being built toward a full **OAuth 2.0 / OpenID Connect** provider. Today it handles user login with SSO sessions, signed JWTs (access, refresh and ID tokens), refresh, logout, user info and role-based access control.

> **Status: early development (about 40%).** Login, refresh, logout and token verification work end to end. The OAuth2 authorization-code flow (`/authorize` with PKCE), consent and client authentication on `/token` are not built yet, so standard OIDC client libraries cannot connect yet. See [TODO.md](TODO.md).

## Features

| Area | What exists |
|---|---|
| Users | Create (CLI), enable/disable, soft delete; bcrypt passwords with a configurable cost |
| Sessions | Server-side SSO sessions in Redis with 256-bit opaque IDs, an `HttpOnly` `SameSite=Lax` cookie, and logout from one device or all of them |
| Tokens | RS256 JWTs with `kid`. Token types are kept separate so a refresh token can't be replayed as an access token. Refresh tokens are bound to the session, so logout kills them |
| Discovery | `/.well-known/openid-configuration` and `/.well-known/jwks.json` |
| Access control | Roles, permissions (`resource:action`) and permissions granted directly to users. They are flattened into the `roles` and `permissions` token claims |
| Clients | Register OAuth clients (CLI), confidential or public; redirect URIs must match exactly; secrets are hashed |
| Hardening | Unknown users and wrong passwords take the same time, account status is only revealed after a correct password, alg=`none` and foreign keys are rejected, request bodies are size-limited, panics are recovered |

## Architecture

The code follows clean / hexagonal architecture. Dependencies point inward: the domain imports nothing from the outer layers.

```
cmd/idp/                     entrypoint: wiring, `serve`, `create-user`, `create-client`
internal/
  domain/                    entities, invariants and repository ports (no infrastructure imports)
    user/ client/ session/ access/ token/
  usecase/
    auth/                    login, refresh, logout, session validation
    admin/                   user and client provisioning
  transport/httpapi/         HTTP handlers (stdlib net/http)
  repository/
    postgres/                users, clients, roles/permissions (pgx v5, raw SQL)
    redis/                   sessions
  infrastructure/
    jwt/                     RS256 token.Service and the RSA key provider
    hasher/                  bcrypt
    redis/                   client factory
  config/                    environment-variable config loader
migrations/                  SQL schema
```

**Where data lives:** PostgreSQL stores users, clients, roles and permissions. Redis stores sessions; their TTL comes from the session expiry. Tokens are stateless JWTs that resource servers verify against the JWKS.

## Quick start

Requirements: Go 1.27+, Docker (for Postgres and Redis).

```bash
# 1. Start Postgres and Redis (the schema is applied automatically on the first start)
docker compose up -d postgres redis

# 2. Configure
cp .env.example .env
set -a; . ./.env; set +a

# 3. Create a user (the password is read from stdin)
echo 'correct-horse-battery' | go run ./cmd/idp create-user -email alice@example.com -username alice

# 4. Optional: register a client so login also returns an ID token
go run ./cmd/idp create-client -name "My App" -grant refresh_token

# 5. Run the server
go run ./cmd/idp serve
```

Or run everything in containers: `docker compose up --build`.

### Try it

```bash
# Login: returns tokens and sets the idp_session cookie
curl -si -c jar.txt localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"alice@example.com","password":"correct-horse-battery"}'

# User info
curl -s localhost:8080/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"

# Refresh
curl -s localhost:8080/token -d grant_type=refresh_token -d refresh_token=$REFRESH_TOKEN

# Logout (ends the session, and with it every refresh token bound to it)
curl -si -b jar.txt -X POST localhost:8080/logout
```

## HTTP API

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Public signing keys |
| `POST` | `/login` | JSON `{identifier, password, client_id?, nonce?}` → tokens plus session cookie. `identifier` is an email or a username |
| `POST` | `/logout` | Ends the session in the cookie; idempotent, returns `204` |
| `POST` | `/token` | Form-encoded. Only `grant_type=refresh_token` is supported for now |
| `GET` | `/userinfo` | Bearer access token → `sub`, `email`, `roles`, `permissions` |

Errors always use the OAuth2 shape: `{"error": "...", "error_description": "..."}`.

## Configuration

All configuration comes from environment variables (see [internal/config/config.go](internal/config/config.go)).

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_DSN` | **required** | |
| `AUTH_ISSUER` | **required** | Public base URL; used as `iss` and in discovery |
| `AUTH_SIGNING_KEY_PATH` | *(empty)* | PEM RSA key (PKCS#1 or PKCS#8, ≥2048 bits). Empty means an ephemeral key (**dev only**) |
| `AUTH_SESSION_TTL` | `24h` | |
| `AUTH_ACCESS_TOKEN_TTL` | `15m` | |
| `AUTH_REFRESH_TOKEN_TTL` | `24h` | Must be ≤ the session TTL |
| `AUTH_ID_TOKEN_TTL` | `1h` | |
| `AUTH_BCRYPT_COST` | `12` | |
| `HTTP_ADDR` | `:8080` | |
| `HTTP_READ_TIMEOUT` / `HTTP_WRITE_TIMEOUT` | `10s` | |
| `HTTP_SHUTDOWN_TIMEOUT` | `15s` | |
| `HTTP_SECURE_COOKIES` | `true` | Set `false` only for local plain HTTP |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_DB` | `localhost` / `6379` / – / `0` | |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## Testing

```bash
go test ./...                     # unit tests (no external services needed)
go test -cover ./...

# Postgres integration tests (skipped unless PG_TEST_DSN is set)
docker run --rm -d --name idp-pg-test -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:17
PG_TEST_DSN=postgres://postgres:test@localhost:55432/postgres go test ./internal/repository/postgres/...
```

Usecases and handlers are tested against in-memory fakes of the domain ports. The JWT service is tested with real RSA keys, including tampering, wrong-issuer, foreign-key, `alg=none` and token-type-confusion cases.

## Roadmap

See [TODO.md](TODO.md) for the step-by-step plan to a complete OIDC provider.

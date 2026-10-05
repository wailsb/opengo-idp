-- Lookup indexes on users(email), users(username), permissions(slug), roles(slug) and
-- clients(client_id) are provided by their UNIQUE constraints; PostgreSQL backs every
-- UNIQUE constraint with a B-tree index, so separate CREATE INDEX statements would be
-- redundant duplicates.

BEGIN;

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    is_deleted    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_username_key UNIQUE (username),
    -- Mirrors user.Delete(): a deleted user is never enabled.
    CONSTRAINT users_deleted_not_enabled_chk CHECK (NOT (is_deleted AND is_enabled))
);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY,
    slug        TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT permissions_slug_key UNIQUE (slug),
    -- Mirrors access.NewPermission: "<resource>:<action>".
    CONSTRAINT permissions_slug_format_chk CHECK (slug ~ '^[^:\s]+:\S+$')
);

CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT roles_slug_key UNIQUE (slug)
);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL,
    permission_id UUID NOT NULL,

    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT role_permissions_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    CONSTRAINT role_permissions_permission_id_fkey
        FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,

    PRIMARY KEY (user_id, role_id),
    CONSTRAINT user_roles_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT user_roles_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE user_direct_permissions (
    user_id       UUID NOT NULL,
    permission_id UUID NOT NULL,

    PRIMARY KEY (user_id, permission_id),
    CONSTRAINT user_direct_permissions_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT user_direct_permissions_permission_id_fkey
        FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

-- The composite primary keys only index the leading column. These cover the reverse
-- lookups and keep ON DELETE CASCADE from roles/permissions from scanning the table.
CREATE INDEX role_permissions_permission_id_idx ON role_permissions (permission_id);
CREATE INDEX user_roles_role_id_idx ON user_roles (role_id);
CREATE INDEX user_direct_permissions_permission_id_idx ON user_direct_permissions (permission_id);

CREATE TABLE clients (
    id                  UUID PRIMARY KEY,
    client_id           TEXT NOT NULL,
    client_secret_hash  TEXT,
    name                TEXT NOT NULL,
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    allowed_grant_types TEXT[] NOT NULL DEFAULT '{}',
    is_confidential     BOOLEAN NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT clients_client_id_key UNIQUE (client_id),
    -- Confidential clients must have a secret; public clients must not.
    CONSTRAINT clients_secret_matches_type_chk
        CHECK (is_confidential = (client_secret_hash IS NOT NULL))
);

COMMIT;

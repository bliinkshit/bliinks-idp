CREATE TABLE IF NOT EXISTS roles (
    id          UUID        PRIMARY KEY NOT NULL,
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id          UUID        PRIMARY KEY NOT NULL,
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS users (
    id                UUID        PRIMARY KEY NOT NULL,
    username          TEXT        NOT NULL UNIQUE,
    password          TEXT        NOT NULL,
    role              UUID        NOT NULL REFERENCES roles(id),
    color             TEXT,
    display_name      TEXT,
    avatar_updated_at TIMESTAMPTZ,
    date_created      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at        TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT        PRIMARY KEY NOT NULL,
    data       TEXT        NOT NULL DEFAULT '{}',
    expires_at BIGINT      NOT NULL,
    user_id    UUID
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS password_resets (
    token_hash  TEXT        NOT NULL PRIMARY KEY,
    user_id     UUID        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);

CREATE TABLE IF NOT EXISTS oauth_clients (
    id          UUID        PRIMARY KEY NOT NULL,
    secret_hash TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_client_redirects (
    id        UUID PRIMARY KEY NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    uri       TEXT NOT NULL,
    UNIQUE(client_id, uri)
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code         TEXT        PRIMARY KEY NOT NULL,
    client_id    UUID        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT        NOT NULL,
    scopes       TEXT        NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT        PRIMARY KEY NOT NULL,
    client_id  UUID        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT        NOT NULL CHECK(kind IN ('access', 'refresh')),
    scopes     TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

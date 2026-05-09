CREATE TABLE IF NOT EXISTS users (
    id                TEXT PRIMARY KEY NOT NULL,
    username          TEXT NOT NULL UNIQUE,
    password          TEXT NOT NULL,
    approved          INTEGER NOT NULL DEFAULT 0,
    admin             INTEGER NOT NULL DEFAULT 0,
    color             TEXT,
    display_name      TEXT,
    avatar_updated_at TEXT,
    date_created      TEXT NOT NULL,
    deleted_at        TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY NOT NULL,
    data       TEXT    NOT NULL DEFAULT '{}',
    expires_at INTEGER NOT NULL,
    user_id    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS password_resets (
    token_hash  TEXT    NOT NULL PRIMARY KEY,
    user_id     TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    used_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);

CREATE TABLE IF NOT EXISTS oauth_clients (
    id            TEXT PRIMARY KEY,
    secret_hash   TEXT NOT NULL,
    name          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_client_redirects (
    id        TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    uri       TEXT NOT NULL,
    UNIQUE(client_id, uri)
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code         TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    used_at      TEXT
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash  TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK(kind IN ('access', 'refresh')),
    scopes      TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

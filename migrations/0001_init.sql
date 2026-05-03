CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY NOT NULL,
    username     TEXT NOT NULL UNIQUE,
    password     TEXT NOT NULL,
    approved     INTEGER NOT NULL DEFAULT 0,
    admin        INTEGER NOT NULL DEFAULT 0,
    color        TEXT,
    display_name TEXT,
    date_created TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY NOT NULL,
    data       TEXT NOT NULL DEFAULT '{}',
    expires_at TEXT NOT NULL,
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

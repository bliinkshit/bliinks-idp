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
    expires_at TEXT NOT NULL
);

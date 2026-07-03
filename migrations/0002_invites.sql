CREATE TABLE IF NOT EXISTS invites (
    id           UUID        PRIMARY KEY NOT NULL,
    code         TEXT        NOT NULL UNIQUE,
    issuer_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_invites_code      ON invites(code);
CREATE INDEX IF NOT EXISTS idx_invites_issuer_id ON invites(issuer_id);

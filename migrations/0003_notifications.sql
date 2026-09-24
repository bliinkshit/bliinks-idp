ALTER TABLE oauth_clients
    ADD COLUMN base_url TEXT;

ALTER TABLE oauth_clients
    ADD COLUMN notifications_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE notifications (
    id              UUID        PRIMARY KEY NOT NULL,
    recipient_id    UUID        NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    client_id       UUID        NOT NULL
        REFERENCES oauth_clients(id) ON DELETE CASCADE,
    text            TEXT        NOT NULL,
    target_path     TEXT        NOT NULL,
    idempotency_key TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at         TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL
        DEFAULT (NOW() + INTERVAL '24 hours'),

    CONSTRAINT notifications_text_length
        CHECK (char_length(text) BETWEEN 1 AND 500),

    CONSTRAINT notifications_target_path
        CHECK (
            target_path LIKE '/%'
            AND target_path NOT LIKE '//%'
            AND char_length(target_path) <= 2048
        ),

    CONSTRAINT notifications_idempotency_length
        CHECK (char_length(idempotency_key) BETWEEN 1 AND 200),

    UNIQUE (client_id, idempotency_key)
);

CREATE INDEX idx_notifications_recipient_created
    ON notifications(recipient_id, created_at DESC);

CREATE INDEX idx_notifications_recipient_unread
    ON notifications(recipient_id, created_at DESC)
    WHERE read_at IS NULL;

CREATE TABLE notification_preferences (
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    client_id UUID NOT NULL
        REFERENCES oauth_clients(id) ON DELETE CASCADE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX idx_notification_preferences_user
    ON notification_preferences(user_id);

CREATE TABLE notification_user_settings (
    user_id UUID PRIMARY KEY NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);  
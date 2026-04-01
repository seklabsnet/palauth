CREATE TABLE user_consents (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id),
    project_id  TEXT NOT NULL REFERENCES projects(id),
    purpose     TEXT NOT NULL,
    granted     BOOLEAN NOT NULL,
    version     TEXT,
    ip          TEXT,
    user_agent  TEXT,
    granted_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_consent_user ON user_consents(user_id);

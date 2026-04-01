CREATE TABLE sessions (
    id              TEXT PRIMARY KEY NOT NULL,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    ip              TEXT,
    user_agent      TEXT,
    device_fp_hash  TEXT,
    acr             TEXT NOT NULL DEFAULT 'aal1',
    amr             JSONB NOT NULL DEFAULT '[]',
    idle_timeout_at TIMESTAMPTZ NOT NULL,
    abs_timeout_at  TIMESTAMPTZ NOT NULL,
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_user ON sessions(user_id) WHERE revoked_at IS NULL;

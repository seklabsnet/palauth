CREATE TABLE encryption_keys (
    id              TEXT PRIMARY KEY NOT NULL,
    project_id      TEXT REFERENCES projects(id),
    user_id         TEXT REFERENCES users(id),
    encrypted_key   BYTEA NOT NULL,
    key_type        TEXT NOT NULL CHECK (key_type IN ('project_dek', 'user_dek')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_ek_project ON encryption_keys(project_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_ek_user ON encryption_keys(user_id) WHERE revoked_at IS NULL;

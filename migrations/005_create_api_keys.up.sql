CREATE TABLE api_keys (
    id          TEXT PRIMARY KEY NOT NULL,
    project_id  TEXT NOT NULL REFERENCES projects(id),
    key_hash    BYTEA NOT NULL UNIQUE,
    key_prefix  TEXT NOT NULL,
    key_type    TEXT NOT NULL CHECK (key_type IN ('public_test', 'secret_test', 'public_live', 'secret_live')),
    name        TEXT,
    last_used   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_apikeys_hash ON api_keys(key_hash) WHERE revoked_at IS NULL;

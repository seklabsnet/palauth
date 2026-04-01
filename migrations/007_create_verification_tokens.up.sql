CREATE TABLE verification_tokens (
    id          TEXT PRIMARY KEY NOT NULL,
    project_id  TEXT NOT NULL REFERENCES projects(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  BYTEA NOT NULL UNIQUE,
    type        TEXT NOT NULL CHECK (type IN ('email_verify', 'password_reset', 'magic_link')),
    used        BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_vt_hash ON verification_tokens(token_hash) WHERE used = false;

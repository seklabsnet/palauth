CREATE TABLE refresh_tokens (
    id          TEXT PRIMARY KEY NOT NULL,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  BYTEA NOT NULL UNIQUE,
    family_id   TEXT NOT NULL,
    parent_id   TEXT,
    used        BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_rt_token ON refresh_tokens(token_hash);
CREATE INDEX idx_rt_family ON refresh_tokens(family_id);

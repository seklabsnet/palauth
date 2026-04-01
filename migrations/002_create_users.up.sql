CREATE TABLE users (
    id              TEXT PRIMARY KEY NOT NULL,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    email_encrypted BYTEA NOT NULL,
    email_hash      BYTEA NOT NULL,
    password_hash   TEXT,
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    banned          BOOLEAN NOT NULL DEFAULT false,
    ban_reason      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_project_email ON users(project_id, email_hash);
CREATE INDEX idx_users_inactive ON users(last_login_at) WHERE banned = false;

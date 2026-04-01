CREATE TABLE admin_users (
    id            TEXT PRIMARY KEY NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

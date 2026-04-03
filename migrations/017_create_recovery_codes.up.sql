-- +goose Up
CREATE TABLE recovery_codes (
  id         TEXT PRIMARY KEY NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  code_hash  TEXT NOT NULL,
  used       BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  used_at    TIMESTAMPTZ
);
CREATE INDEX idx_recovery_codes_user ON recovery_codes(user_id, project_id) WHERE used = false;

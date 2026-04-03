-- +goose Up
CREATE TABLE identities (
  id               TEXT PRIMARY KEY NOT NULL,
  project_id       TEXT NOT NULL REFERENCES projects(id),
  user_id          TEXT NOT NULL REFERENCES users(id),
  provider         TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  provider_data    JSONB NOT NULL DEFAULT '{}',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_identity_provider ON identities(project_id, provider, provider_user_id);
CREATE INDEX idx_identity_user ON identities(user_id);

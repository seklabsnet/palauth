-- +goose Up
CREATE TABLE mfa_enrollments (
  id               TEXT PRIMARY KEY NOT NULL,
  project_id       TEXT NOT NULL REFERENCES projects(id),
  user_id          TEXT NOT NULL REFERENCES users(id),
  type             TEXT NOT NULL CHECK (type IN ('totp', 'webauthn', 'sms', 'email')),
  secret_encrypted BYTEA,
  verified         BOOLEAN NOT NULL DEFAULT false,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_user ON mfa_enrollments(user_id) WHERE verified = true;
